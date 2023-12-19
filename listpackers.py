# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import io
import logging
import struct
from typing import List, Tuple


from volatility3.framework import interfaces, exceptions, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, dlllist
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
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
WELL_KNOWN_SECTION_PACKER_NAMES = ["upx0", "upx1","upx2",
                                   "mpress1", "mpress2",
                                   "aspack",
                                   "kanal",
                                   "dae",
                                   "encrypt",
                                   "svkp",
                                   "petite",
                                   "rlpack",
                                   "themida",
                                   "winlicen",
                                   "yp",
                                   "cc1", "cc2",
                                   "xcomp",
                                   "rc4"] 

class ListPackers(interfaces.plugins.PluginInterface):
    "Display packed processes"

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
        self.size_of_pfn = self.ntkrnlmp.get_type("_MMPFN").size
        _pointer_struct = struct.Struct("<Q") if self.ntkrnlmp.get_type('pointer').size == 8 else struct.Struct('I')
        self.page_file_db = int(_pointer_struct.unpack(self.context.layers[self.kaddr_space].read(self.ntkrnlmp.get_symbol('MmPfnDatabase').address + self.kvo, self.ntkrnlmp.get_type('pointer').size))[0])

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
        ]

    def get_section_information(
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
        #pe.parse_data_directories(
        #    [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        #)
        section_char_name = []
        for sec in pe.sections:
            section_char_name.append((sec.Characteristics, sec.Name.replace(b'\x00',b''), sec.VirtualAddress, sec.Misc_VirtualSize))
        
        pe.close()
        return section_char_name

    def _generator(self, data):
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        # now go through the process and dll lists
        for proc in data:
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

            for entry in proc.load_order_modules():
                is_packed = 'False'
                packer_name = 'Unknown'
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                try:
                    DllBase = format_hints.Hex(entry.DllBase)
                except exceptions.InvalidAddressException:
                    DllBase = renderers.UnreadableValue()

                try:

                    section_packed_list = self.get_section_information(
                        self._context, pe_table_name, proc_layer_name, entry.DllBase
                    )

                    for section_charecteristics, section_name, section_start, section_size in section_packed_list:
                        section_end = section_start + section_size
                        rwx_counter = 0
                        no_rwx_counter = 0
                        prot_counter = 0

                        # Check if the page marked in the PFN as executable
                        for c_r_address in range(section_start, section_end+1, 0x1000):
                            c_v_address = c_r_address + int(entry.DllBase)
                            if not self.context.layers[proc_layer_name].is_valid(c_v_address):
                                continue
                            c_address = self.context.layers[proc_layer_name].translate(c_v_address)[0]
                            pfn_entry = self.ntkrnlmp.object("_MMPFN", int(self.page_file_db)+self.size_of_pfn*(c_address >> 12) - self.kvo)
                            prot = int(pfn_entry.OriginalPte.u.Hard.NoExecute)
                            prot_counter += prot
                            if pfn_entry.OriginalPte.u.Soft.Protection == 6: # RWX
                                rwx_counter += 1
                            else:
                                no_rwx_counter +=1
                        if rwx_counter > no_rwx_counter or section_name.lower() in WELL_KNOWN_SECTION_PACKER_NAMES or section_charecteristics & (IMAGE_SCN_MEM_EXECUTE+IMAGE_SCN_MEM_WRITE) == section_charecteristics:
                            is_packed = 'True'
                            for c_packer in WELL_KNOWN_SECTION_PACKER_NAMES:
                                if section_name.lower() in c_packer.encode():
                                    packer_name = section_name.lower().decode()
                                    break
                            yield (
                                0,
                                (
                                    proc_id,
                                    "{}.{}.{}".format(proc.ImageFileName.cast(
                                        "string",
                                        max_length=proc.ImageFileName.vol.count,
                                        errors="replace",
                                    ),
                                    DllBase,
                                    BaseDllName),
                                    is_packed,
                                    packer_name,
                                ),
                            )
                except (exceptions.InvalidAddressException, ValueError, AttributeError) as ex:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Error while pefile {process_name}, {proc_id}\n{ex}",
                    )

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
