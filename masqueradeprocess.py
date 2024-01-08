# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
import io
import logging
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

class MasqueradeProcess(interfaces.plugins.PluginInterface):
    "Display masquerade processes by original name"

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

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

    def get_pe_file(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        base_address: int,
    ) -> Tuple[Tuple[str, str]]:
        """Get pefile PE object from file.

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
        return pe

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

            # break after the first, since we want only the executable and not other dlls
            # so entry would only be the executable name
            for entry in proc.load_order_modules():
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                try:
                    DllBase = format_hints.Hex(entry.DllBase)
                except exceptions.InvalidAddressException:
                    DllBase = renderers.UnreadableValue()

                try:                    
                    original_name = -1
                    c_pefile = self.get_pe_file(self._context, pe_table_name, proc_layer_name, entry.DllBase)
                    c_pefile.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
                    file_info = c_pefile.FileInfo
                    for c_fn in file_info:
                        for entry in c_fn:
                            if entry.name == "StringFileInfo":
                                for string_entry in entry.StringTable:
                                    if b"OriginalFilename" in string_entry.entries:
                                        original_name = string_entry.entries[b"OriginalFilename"].decode()

                    # if we cant find this file original name then continue
                    if original_name == -1 or original_name.lower() == BaseDllName.lower():
                        break  
                                    
                    yield (
                        0,
                        (
                            proc_id,
                            process_name,
                            DllBase,
                            BaseDllName,
                            original_name,
                        ),
                    )
                except (exceptions.InvalidAddressException, ValueError, AttributeError) as ex:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Error while pefile {process_name}, {proc_id}\n{ex}",
                    )
                break

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process Name", str),
                ("Image Address", int),
                ("Image Name", str),
                ("Original Name", str),
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
