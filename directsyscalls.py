# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import io
import logging
import struct
from typing import List, Tuple, Iterable



from volatility3.framework import interfaces, exceptions, renderers, constants, symbols
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, dlllist, vadinfo, malfind
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
            #requirements.VersionRequirement(
            #    name="malfind", component=malfind.Malfind, version=(2, 0, 0)
            #),
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
    def list_injections(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        symbol_table: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[interfaces.objects.ObjectInterface, bytes]]:
        """Generate memory regions for a process that may contain injected
        code. same as malfind function but instead reading 64 bytes lets read all the vad, we can
        merge this function with additional arg extract_size to master in the future

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
                if malfind.Malfind.is_vad_empty(proc_layer, vad):
                    continue

                data = proc_layer.read(vad.get_start(), vad.get_size(), pad=True)
                yield vad, data

    def extract_reg_at_offset(self, prev_instructions, reg_id, offset=0):
        """ Extract the value of eax at specific offset from disassembly
        note: could be better identify (in some cases) using unicorn
        Return:
            eax/rax value
        """
        c_index = -1
        instruction_to_reg = []
        for inst in prev_instructions[::-1]:
            
            # get eax value from the mov mnemonic
            if inst.mnemonic == 'mov' and (inst.op_str.startswith('eax') or inst.op_str.startswith('rax')):
                data_to_display = '\n'
                eax_new_val = inst.operands[1].imm
                instruction_to_reg.append(inst)
                for i in instruction_to_reg[::-1]:
                    data_to_display += f"{hex(offset+i.address)}\t{i.mnemonic} {i.op_str}\n"
                return eax_new_val, data_to_display

            # extract the value from memory (we can use this function recursive to extract the other registers inside the [] if needed)
            elif inst.mnemonic == 'mov' and (inst.op_str.startswith('eax') or inst.op_str.startswith('rax')):
                return None, ''#pass # prev_instructions[:c_index??]

            # we dont know how to get this value from pop
            elif inst.mnemonic == 'pop' and (inst.op_str.startswith('eax') or inst.op_str.startswith('rax')):
                return None, ''#pass 

            # we dont know how to get this value from pop
            elif inst.mnemonic in ['test', '???']:
                return None, ''#pass

            c_index -= 1
            instruction_to_reg.append(inst)
            
        return None, None


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
            # get all ntdll exports
            ntdll_exports = self.get_dll_exports(
                self._context, pe_table_name, proc_layer_name, entry.DllBase
            )
        except exceptions.InvalidAddressException as ex:#(exceptions.InvalidAddressException, ValueError, AttributeError) as ex:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Error while pefile {process_name}, {proc_id}\n{ex}",
            )
            return
        
        syscalls = sorted([i for i in ntdll_exports if i[1] and i[1].startswith(b'Zw')])

        for proc in process_list:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad, data in self.list_injections(
                self.context, kernel.layer_name, kernel.symbol_table_name, proc
            ):
                #print(data[0x1200:0x1300], type(data))
                # if we're on a 64 bit kernel, we may still need 32 bit disasm due to wow64
                if is_32bit_arch or proc.get_is_wow64():
                    if has_capstone:
                        eax_or_rax_id = capstone.x86.X86_REG_EAX
                        capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                        capst.detail = True
                else:
                    if has_capstone:
                        eax_or_rax_id = capstone.x86.X86_REG_RAX
                        capst = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                        capst.detail = True
                
                prev_instructions = []
                syscall_like = [b'\x0f\x05', # Syscall
                                #b'\x0f\x34', # Sysenter # remove a lot of FP's and kinda old and not really used (enable if you use such os)
                                #b'\xcd\x2e', # int 0x2e
                                 ]
                start_address = vad.get_start()
                extend_after_by = 20
                for c_syscall in syscall_like:
                    c_syscall_len = len(c_syscall)
                    for c_byte_index in range(0, len(data) - c_syscall_len, 1):
                        c_data = data[c_byte_index:c_byte_index+c_syscall_len]
                        if c_data == c_syscall:

                            # Try to dissasembly the data to find the syscall instruction
                            for start_from in range(25 if c_byte_index > 25 else c_byte_index, 0, -1):
                                extended_chunk = data[c_byte_index-start_from:c_byte_index+extend_after_by]
                                inst_data = "\n"
                                flag_good_data = False
                                prev_instructions = []
                                for i in capst.disasm(extended_chunk, 0):
                                    prev_instructions.append(i)
                                    inst_data += f"{hex((start_address+c_byte_index-start_from)+i.address)}\t{i.mnemonic} {i.op_str}"

                                    # we decide that the data is good if the disass contains our instruction
                                    if c_syscall in bytes(i.opcode)[:c_syscall_len]:
                                        #print(start_from)
                                        
                                        # display only current syscall and above
                                        if start_from > 10:
                                            inst_data = ''
                                            prev_instructions = []
                                            continue

                                        if flag_good_data:
                                            break

                                        eax, data_to_display = self.extract_reg_at_offset(prev_instructions, eax_or_rax_id, vad.get_start())
                                        if eax:
                                            c_direct_syscall = syscalls[eax][1].decode()
                                        else:
                                            eax = -1
                                            c_direct_syscall = 'failed to identify'
                                        inst_data += f"\t<{c_direct_syscall} [syscall]>\n"
                                        flag_good_data = True
                                    else:
                                        inst_data += "\n"
                                
                                # if we found our hash in the Dissasembly -> break
                                if flag_good_data:
                                    c_byte_index += extend_after_by
                                    yield (
                                            0,
                                            (
                                                proc.UniqueProcessId,
                                                process_name,
                                                format_hints.Hex(vad.get_start()),
                                                format_hints.Hex(vad.get_end()),
                                                vad.get_tag(),
                                                vad.get_protection(
                                                    vadinfo.VadInfo.protect_values(
                                                        self.context,
                                                        kernel.layer_name,
                                                        kernel.symbol_table_name,
                                                    ),
                                                    vadinfo.winnt_protections,
                                                ),
                                                vad.get_commit_charge(),
                                                vad.get_private_memory(),
                                                eax,
                                                c_direct_syscall,
                                                inst_data,
                                            ),
                                        )
                                    break

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start VPN", format_hints.Hex),
                ("End VPN", format_hints.Hex),
                ("Tag", str),
                ("Protection", str),
                ("CommitCharge", int),
                ("PrivateMemory", int),
                ("Syscall EAX", int),
                ("Syscall Funtion", str),
                ("Disasm", str),
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
