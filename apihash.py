# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import Iterable, Tuple

from volatility3.framework import interfaces, symbols, exceptions
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo, malfind

import sqlite3
import os
import ctypes

############################################################
# SQL queries
############################################################​
sql_get_all_hash_symbols = '''
select 
    h.hash_val,
    h.symbol_name,
    l.lib_name, 
    t.hash_name, 
    t.hash_size,
    t.hash_type
from symbol_hashes h,
     source_libs l, 
     hash_types t
where
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type;
'''

sql_get_all_hash_types_temp = '''
select 
    h.hash_val,
    h.symbol_name,
    l.lib_name, 
    t.hash_name, 
    t.hash_size,
    t.hash_type
from symbol_hashes h,
     source_libs l, 
     hash_types t
where
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type;
'''

sql_lookup_hash_value = '''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type;
'''

sql_lookup_hash_type_value = '''
select
    h.hash_val, 
    h.symbol_name, 
    l.lib_name, 
    t.hash_name, 
    t.hash_size,
    t.hash_type
from 
    symbol_hashes h, 
    source_libs l, 
    hash_types t 
where 
    h.hash_val=? and 
    h.lib_key=l.lib_key and 
    h.hash_type=t.hash_type and
    h.hash_type=?;
'''

sql_get_all_hash_types = '''
select 
    hash_type,
    hash_size,
    hash_name,
    hash_code
from hash_types;
'''

sql_find_source_lib_by_name = '''
select
    lib_key
from 
    source_libs
where 
    lib_name=?;
'''

sql_adjust_cache_size = '''
PRAGMA cache_size=200000;
'''

############################################################
# Row wrappers
############################################################

class SymbolHash(object):
    def __init__(self, hashVal, symbolName, libName, hashName, hashSize, hashType):
        self.hashVal = hashVal
        self.symbolName = symbolName
        self.libName = libName
        self.hashName = hashName
        self.hashSize = hashSize
        self.hashType = hashType

    def __str__(self):
        return '%s:0x%08x %s!%s' % (self.hashName, self.hashVal, self.libName, self.symbolName)

class HashType(object):
    def __init__(self, hashType, hashSize, hashName, hashCode):
        self.hashType = hashType
        self.hashSize = hashSize
        self.hashName = hashName
        self.hashCode = hashCode
        
class HashHit(object):
    def __init__(self, ea, symHash):
        self.ea = ea
        self.symHash = symHash

############################################################
# Query classes
############################################################

class DbStore(object):
    '''
    Used to access the hash db.
    '''

    def __init__(self, dbPath):
        self.dbPath = dbPath
        self.conn = sqlite3.connect(dbPath)
        self.conn.execute(sql_adjust_cache_size)

    def close(self):
        self.conn.close()
        self.conn = None

    def getSymbolByHash(self, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_value, (ctypes.c_int64(hashVal).value,))
        for row in cur:
            # logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

    def getAllHashTypes(self):
        '''
        Returns a list of HashType objects stored in the DB.
        '''
        retArr = []
        cur = self.conn.execute(sql_get_all_hash_types)
        for row in cur:
            retArr.append(HashType(*row))
        return retArr

    def getSymbolByTypeHash(self, hashType, hashVal):
        '''
        Returns list of SymbolHash objects for requested hashvalue.
        List is empty for no hits
        '''
        retList = []
        cur = self.conn.execute(sql_lookup_hash_type_value, (ctypes.c_int64(hashVal).value, hashType))

        for row in cur:
            # logger.debug("Found hits for value: %08x", hashVal)
            sym = SymbolHash(*row)
            retList.append(sym)
        return retList

    def initAllSymbolHashes(self):
        '''
        Initiate a dictionary of list with all the hashVal -> [symbol hashes]
        '''
        cur = self.conn.execute(sql_get_all_hash_symbols)
        self.symbolHashes = dict()
        for row in cur:
            symbolHash = SymbolHash(*row)

            if symbolHash.hashVal in self.symbolHashes:
                self.symbolHashes[symbolHash.hashVal].append(symbolHash)
            else:
                self.symbolHashes[symbolHash.hashVal] = list()
                self.symbolHashes[symbolHash.hashVal].append(symbolHash)

class SearchLauncher(object):
    '''
    used to query DbStore by hash
    '''
    def __init__(self):
        dbFile = os.path.abspath(os.path.join(os.path.dirname(__file__), 'sc_hashes.db'))
        self.dbstore = DbStore(dbFile)
        self.dbstore.initAllSymbolHashes()

    def get_hits(self, q_hash):
        '''
        Using DbStore dict (symbolHashes) this function return the symbol name (as a list) from a symbol hash
        '''
        if q_hash in self.dbstore.symbolHashes:
            return self.dbstore.symbolHashes[q_hash]

############################################################
# Volatility code
############################################################

vollog = logging.getLogger(__name__)

class ApiHash(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

    _required_framework_version = (2, 5, 2)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract injected hashdb VADs",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            #requirements.VersionRequirement(
            #    name="malfind", component=malfind.Malfind, version=(2, 4, 0)
            #),
        ]

    @classmethod
    def list_injections(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        symbol_table: str,
        proc: interfaces.objects.ObjectInterface,
    ) -> Iterable[Tuple[interfaces.objects.ObjectInterface, bytes]]:
        """Generate memory regions for a process that may contain injected
        code. same as malfind function but instead reading 64 bytes lets read all the vad we can
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

    def _generator(self, procs):
        # determine if we're on a 32 or 64 bit kernel
        try:
            has_capstone = True
            import capstone
        except ImportError:
            has_capstone = False
            vollog.debug("Disassembly library capstone not found")

        self.launcher = SearchLauncher()
        kernel = self.context.modules[self.config["kernel"]]

        is_32bit_arch = not symbols.symbol_table_is_64bit(
            self.context, kernel.symbol_table_name
        )

        for proc in procs:
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

                # we cant really get the dissas since we dont know where this funciton start
                #disasm = interfaces.renderers.Disassembly(
                #    data, vad.get_start(), architecture
                #)

                hits_output = "\n"
                start_address = vad.get_start()

                # iterate all the data to find hash
                for c_byte_index in range(2, len(data)-4):
                    chunk_as_is = data[c_byte_index:c_byte_index+4]
                    # TODO check endians!
                    chunk_as_is = chunk_as_is[::-1] #if little
                    chunk_as_is_hex = chunk_as_is.hex()
                    c_chunk = int.from_bytes(data[c_byte_index:c_byte_index+4], byteorder='little') #if little
                    c_hits = self.launcher.get_hits(c_chunk)
                    
                    # add the hits to our output (exclude FP if we have capstone)
                    if c_hits:
                        # before we add this hit to the list we want to make sure its TP -> validate it came after mov or push
                        if has_capstone:
                            for i in capst.disasm(data[c_byte_index-2:c_byte_index+4], 0):
                                if "push" == i.mnemonic:
                                    break
                            else:
                                for i in capst.disasm(data[c_byte_index-1:c_byte_index+4], 0):
                                    if "mov" == i.mnemonic:
                                        break
                                else:
                                    continue
                        # add all the hits to our output
                        if has_capstone:
                            for cc_hit in c_hits:
                                hits_output += f"{(start_address+c_byte_index):x}: {chunk_as_is} - {cc_hit.libName}!{cc_hit.symbolName} ({cc_hit.hashName})"

                                # Try to dissasembly the data to make the make the investigator easy life (identify paretn such as Metasploit/TP/FP/...)
                                for start_from in range(25 if c_byte_index > 25 else c_byte_index, 0, -1):
                                    extended_chunk = data[c_byte_index-start_from:c_byte_index+20]
                                    inst_data = "\n"
                                    flag_good_data = False
                                    for i in capst.disasm(extended_chunk, 0):
                                        inst_data += f"{hex((start_address+c_byte_index-start_from)+i.address)}\t{i.mnemonic} {i.op_str}"

                                        # we decide that the data is good if the disass contains our instruction
                                        #print(chunk_as_is_hex, i.op_str, type(chunk_as_is_hex), type(i.op_str))
                                        if chunk_as_is_hex in i.op_str:
                                            inst_data += f"\t<{cc_hit.libName}!{cc_hit.symbolName} [hashdb]>\n"
                                            flag_good_data = True
                                        else:
                                            inst_data += "\n"
                                    
                                    # if we found our hash in the Dissasembly -> break
                                    if flag_good_data:
                                        break

                                hits_output += inst_data
                                hits_output += '\n'

                        else:
                            for cc_hit in c_hits:
                                chances = 99/str(chunk_as_is.replace(b'\x00', b'')).count("\\x")
                                hits_output += f"{(start_address+c_byte_index):x}: {chunk_as_is} - {cc_hit.libName}!{cc_hit.symbolName} ({cc_hit.hashName}) - fp changes (about {chances}% FP!)\n"

                # add \n to display it better
                if hits_output == '\n':
                    continue

                file_output = "Disabled"
                if self.config["dump"]:
                    file_output = "Error outputting to file"
                    try:
                        file_handle = vadinfo.VadInfo.vad_dump(
                            self.context, proc, vad, self.open
                        )
                        file_handle.close()
                        file_output = file_handle.preferred_filename
                    except (exceptions.InvalidAddressException, OverflowError) as excp:
                        vollog.debug(
                            "Unable to dump PE with pid {0}.{1:#x}: {2}".format(
                                proc.UniqueProcessId, vad.get_start(), excp
                            )
                        )

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
                        file_output,
                        #format_hints.HexBytes(data),
                        #disasm,
                        hits_output,
                    ),
                )

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
                ("File output", str),
                #("Hexdump", format_hints.HexBytes),
                #("Disasm", interfaces.renderers.Disassembly),
                ("hashDB", str)
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
