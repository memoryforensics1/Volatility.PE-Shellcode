# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import io
import logging
import struct
from typing import List, Tuple, Iterable



from volatility3.framework import interfaces, exceptions, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, dlllist, vadinfo
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.renderers import format_hints



vollog = logging.getLogger(__name__)
try:
    import pefile
except ImportError:
    vollog.info(
        "Python pefile module not found, plugin (and dependent plugins) not available"
    )
    raise
 

class DirectSyscalls(interfaces.plugins.PluginInterface):
    "Display DirectSyscalls"

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config['primary'] = self.context.modules[self.config['kernel']].layer_name
        self.config['nt_symbols'] = self.context.modules[self.config['kernel']].symbol_table_name
        self.kaddr_space = self.config['primary']
        self._config = self.config
        self.kvo = self.context.layers[self.kaddr_space].config["kernel_virtual_offset"]
        self.ntkrnlmp = self._context.module(self.config['nt_symbols'],
                                             layer_name=self.kaddr_space,
                                             offset=self.kvo)
        # self.size_of_pfn = self.ntkrnlmp.get_type("_MMPFN").size
        # _pointer_struct = struct.Struct("<Q") if self.ntkrnlmp.get_type('pointer').size == 8 else struct.Struct('I')
        # self.page_file_db = int(_pointer_struct.unpack(self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmPfnDatabase').address + self.kvo, self.ntkrnlmp.get_type('pointer').size))[0])

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="dlllist", component=dlllist.DllList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
        ]

    def get_dll_exports(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        base_address: int,
    ) -> Tuple[Tuple[str, str]]:
        """Get File and Product version information from PE files.

        Args:
            context: volatility context on which to operate
            pe_table_name: name of the PE table
            layer_name: name of the layer containing the PE file
            base_address: base address of the PE (where MZ is found)
        """

        if layer_name is None:
            raise TypeError("Layer must be a string not None")

        pe_data = io.BytesIO()

        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            offset=base_address,
            layer_name=layer_name,
        )

        for offset, data in dos_header.reconstruct():
            pe_data.seek(offset)
            pe_data.write(data)

        pe = pefile.PE(data=pe_data.getvalue(), fast_load=True)
        pe.parse_data_directories()

        exports = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #print(exp.address, exp.address_offset)
            exports.append(((pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal))
        return exports

    @classmethod
    def is_vad_empty(cls, proc_layer, vad):
        """Check if a VAD region is either entirely unavailable due to paging,
        entirely consisting of zeros, or a combination of the two. This helps
        ignore false positives whose VAD flags match task._injection_filter
        requirements but there's no data and thus not worth reporting it.

        Args:
            proc_layer: the process layer
            vad: the MMVAD structure to test

        Returns:
            A boolean indicating whether a vad is empty or not
        """

        CHUNK_SIZE = 0x1000
        all_zero_page = b"\x00" * CHUNK_SIZE

        offset = 0
        vad_length = vad.get_size()

        while offset < vad_length:
            next_addr = vad.get_start() + offset
            if (
                proc_layer.is_valid(next_addr, CHUNK_SIZE)
                and proc_layer.read(next_addr, CHUNK_SIZE) != all_zero_page
            ):
                return False
            offset += CHUNK_SIZE

        return True

    @classmethod
    def list_injections(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        symbol_table: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[interfaces.objects.ObjectInterface, bytes]]:
        """Generate memory regions for a process that may contain injected
        code.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_layer_name: The name of the kernel layer from which to read the VAD protections
            symbol_table: The name of the table containing the kernel symbols
            proc: an _EPROCESS instance

        Returns:
            An iterable of VAD instances and the first 64 bytes of data containing in that region
        """
        proc_id = "Unknown"
        try:
            proc_id = proc.UniqueProcessId
            proc_layer_name = proc.add_process_layer()
        except exceptions.InvalidAddressException as excp:
            vollog.debug(
                "Process {}: invalid address {} in layer {}".format(
                    proc_id, excp.invalid_address, excp.layer_name
                )
            )
            return

        proc_layer = context.layers[proc_layer_name]

        for vad in proc.get_vad_root().traverse():
            protection_string = vad.get_protection(
                vadinfo.VadInfo.protect_values(
                    context, kernel_layer_name, symbol_table
                ),
                vadinfo.winnt_protections,
            )
            write_exec = "EXECUTE" in protection_string and "WRITE" in protection_string

            # the write/exec check applies to everything
            if not write_exec:
                continue

            if (vad.get_private_memory() == 1 and vad.get_tag() == "VadS") or (
                vad.get_private_memory() == 0
                and protection_string != "PAGE_EXECUTE_WRITECOPY"
            ):
                if cls.is_vad_empty(proc_layer, vad):
                    continue

                data = proc_layer.read(vad.get_start(), vad.get_size(), pad=True)
                yield vad, data


    def _generator(self, data):
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )
        try:
            has_capstone = True
            import capstone
        except ImportError:
            has_capstone = False
            vollog.debug("Disassembly library capstone not found")

        kernel = self.context.modules[self.config["kernel"]]

        is_32bit_arch = not symbols.symbol_table_is_64bit(
            self.context, kernel.symbol_table_name
        )
        
        process_list = [proc for proc in data]

        # now go through the process and dll lists
        for proc in process_list:
            proc_id = "Unknown"
            print('asd')
            try:
                proc_id = proc.UniqueProcessId
                process_name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )
                continue
                    # if we're on a 64 bit kernel, we may still need 32 bit disasm due to wow64
            if is_32bit_arch or proc.get_is_wow64():
                architecture = "intel"
                if has_capstone:
                    capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            else:
                architecture = "intel64"
                if has_capstone:
                    capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            for entry in proc.load_order_modules():

                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                try:
                    DllBase = format_hints.Hex(entry.DllBase)
                except exceptions.InvalidAddressException:
                    DllBase = renderers.UnreadableValue()

                if BaseDllName == 'ntdll.dll':
                    break

        try:
            ntdll_exports = self.get_dll_exports(
                self._context, pe_table_name, proc_layer_name, entry.DllBase
            )
        except exceptions.InvalidAddressException as ex:#(exceptions.InvalidAddressException, ValueError, AttributeError) as ex:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Error while pefile {process_name}, {proc_id}\n{ex}",
            )
            print('we fucked')
            return
        
        for export in ntdll_exports:
            print(export)
        syscalls = sorted([i for i in ntdll_exports if i[1] and i[1].startswith(b'Zw')])
        addr = syscalls[0][0]
        #syscalls = [(c_name.decode(), c_address, c_oridinal) if c_name.startswith(b'Nt') for c_name, c_address, c_oridinal in ntdll_exports]
        print(syscalls)
        proc_layer_name = proc.add_process_layer()
        proc_layer = self.context.layers[proc_layer_name]
        for item in syscalls:
            addr = item[0]
            data = proc_layer.read(addr, 16, pad=True)
            for i in capst.disasm(data, 0):
                print(i)

        for proc in process_list:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad, data in self.list_injections(
                self.context, kernel.layer_name, kernel.symbol_table_name, proc
            ):
                # if we're on a 64 bit kernel, we may still need 32 bit disasm due to wow64
                if is_32bit_arch or proc.get_is_wow64():
                    architecture = "intel"
                    if has_capstone:
                        capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                else:
                    architecture = "intel64"
                    if has_capstone:
                        capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            
                for i in capst.disasm(data, 0):
                    if 'int 0x2e' in str(i).lower() or 'sysenter' in str(i).lower() or 'syscall' in str(i).lower() or 'int 2e' in str(i).lower():
                        print(i)


    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Is Packed", str),
                ("Packer Name", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
