#  Supporting class for PE parsing
#
# MIT License
# 
# Copyright (c) 2023 Frank Block, <research@f-block.org>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import logging, pefile, codecs
from typing import Callable, List, Generator, Iterable, Type, Optional

from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows.apisearch import ImportExportParser
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

# We support versions 1 and 2
framework_version = constants.VERSION_MAJOR
if framework_version == 1:
    kernel_layer_name = 'primary'
    kernel_reqs = [requirements.TranslationLayerRequirement(name = kernel_layer_name,
                                                            description = 'Memory layer for the kernel',
                                                            architectures = ["Intel32", "Intel64"]),
                   requirements.SymbolTableRequirement(name = "nt_symbols",
                                                       description = "Windows kernel symbols")]
elif framework_version == 2:
    kernel_layer_name = 'kernel'
    kernel_reqs = [requirements.ModuleRequirement(name = kernel_layer_name,
                                                  description = 'Windows kernel',
                                                  architectures = ["Intel32", "Intel64"])]

else:
    # The highest major version we currently support is 2.
    raise RuntimeError(f"Framework interface version {framework_version} is "
                        "currently not supported.")


class PeWrapper(ImportExportParser):

    def __init__(self, context, config, config_path, vad, dll_entry, proc_layer_name, wow64, extensions=['img', 'dat', 'vacb']):
        self.export_dict = None
        self.import_dict = None
        self.api_offsets = None
        self.context = context
        self.config = config
        self.config_path = config_path
        self.vad = vad
        self.dll_entry = dll_entry
        self.proc_layer_name = proc_layer_name
        self.wow64 = wow64
        self.parsed_files = None
        self.file_handles = list()
        self.pe_files = list()
        tmp_files = list(self._get_parsed_pe_files(context, config, config_path, vad, extensions))
        if tmp_files:
            self.parsed_files = dict()
            for mem_obj, ext, file_handle, pe_file in tmp_files:
                self.parsed_files[ext] = [mem_obj, file_handle, pe_file]
                self.file_handles.append(file_handle)
                self.pe_files.append(pe_file)


    def get_section_by_vaddr(self, vaddr):
        return self.get_section_by_rva(vaddr - self.vad.get_start())


    def get_section_by_rva(self, rva):
        section = None

        for pe_file in self.pe_files:
            if not pe_file:
                continue

            section = pe_file.get_section_by_rva(rva)
            if section:
                return section

        return None


    def get_section_name_by_rva(self, rva):
        section = self.get_section_by_rva(rva)

        if section:
            try:
                return codecs.decode(section.Name, 'utf-8').rstrip('\x00')
            except Exception:
                return None

        for pe_file in self.pe_files:
            if not pe_file:
                continue

            if rva < pe_file.OPTIONAL_HEADER.SizeOfHeaders:
                return "Header"

        return None


    def get_section_name_by_vaddr(self, vaddr):
        return self.get_section_name_by_rva(vaddr - self.vad.get_start())


    def get_context_by_vaddr(self, vaddr):
        return self.get_context_by_rva(vaddr - self.vad.get_start())


    def get_context_by_rva(self, rva):
        for pe_file in self.pe_files:
            if not pe_file:
                continue

            if isinstance(pe_file, pefile.PE):
                if hasattr(pe_file, "OPTIONAL_HEADER") and hasattr(
                    pe_file.OPTIONAL_HEADER, "DATA_DIRECTORY"):
                    for directory in pe_file.OPTIONAL_HEADER.DATA_DIRECTORY:
                        if directory is None:
                            continue
                        va = directory.VirtualAddress
                        if va <= rva < (va + directory.Size):
                            return directory.name


    def _parse_imports(self):
        self.import_dict = dict()
        for file_handle in self.file_handles:
            self.import_dict.update(self.get_imports(file_handle, byte_index=False, wow64=self.wow64))
        if self.dll_entry:
            self.import_dict.update(self.get_imports_from_module(self.context, self.config, self.config_path, self.vad, self.dll_entry, self.proc_layer_name, byte_index=False, wow64=self.wow64))


    def _parse_exports(self):
        self.export_dict = dict()
        for pe_file in self.pe_files:
            for key, (dll_entry, exp) in self.get_exports(self.dll_entry, pe_file=pe_file, img_base=self.vad.get_start(), byte_index=False, wow64=self.wow64).items():
                if key in self.export_dict:
                    self.export_dict[key]['exp_objs'].append(exp)
                else:
                    self.export_dict[key] = {'dll_entry': dll_entry, 'exp_objs': [exp]}
        if self.dll_entry:
            for key, (dll_entry, exp) in self.get_exports_from_module(self.context, self.config, self.config_path, self.vad, self.dll_entry, self.proc_layer_name, byte_index=False, wow64=self.wow64).items():
                if key in self.export_dict:
                    self.export_dict[key]['exp_objs'].append(exp)
                else:
                    self.export_dict[key] = {'dll_entry': dll_entry, 'exp_objs': [exp]}

        self.api_offsets = sorted(self.export_dict.keys())


    def get_export_for_name(self, name):
        if not self.export_dict:
            self._parse_exports()

        if not self.export_dict:
            return None

        for offset, data in self.export_dict.items():
            exp_objs = data['exp_objs']
            exp_names = ", ".join(set([codecs.decode(x.name, 'utf-8') for x in exp_objs if x.name]))
            if name in exp_names:
                return (offset, data)

        return None


    def get_export_with_ctx_for_vaddr(self, vaddr):
        if not self.export_dict:
            self._parse_exports()

        result = {'repr': 'N/A'}

        if not self.api_offsets:
            return result

        prev_api_off = 1 << 64
        api_hit = None

        # Now we are trying to get the corresponding function name
        if vaddr < self.api_offsets[0]:
            return result

        next_api_offset = None
        for api_offset in self.api_offsets:
            if prev_api_off <= vaddr < api_offset:
                api_hit = prev_api_off
                next_api_offset = api_offset
                break
            prev_api_off = api_offset
        # The previous algorithm searched for hit between two exported functions.
        # The last step is to look for a hit in the last function
        if not api_hit and self.api_offsets[-1] <= vaddr < self.api_offsets[-1] + 0x100:
            api_hit = self.api_offsets[-1]

        if not api_hit:
            return result

        exp_objs = self.export_dict[api_hit]['exp_objs']
        ordinal = exp_objs[0].ordinal
        result['ordinal'] = ordinal
        exp_names = ", ".join(set([codecs.decode(x.name, 'utf-8') for x in exp_objs if x.name]))
        result['name'] = exp_names if exp_names else "N/A"
        result['repr'] = exp_names if exp_names else ("ordinal: " + str(ordinal))
        offset = vaddr - api_hit
        result['offset'] = offset
        if next_api_offset is not None:
            result['distance_to_next_api'] = next_api_offset - vaddr
        result['repr'] += f" + 0x{offset:x}"

        return result


    def get_pe_data(self, rva, length):
        data = None
        for pe_file in self.pe_files:
            data = pe_file.get_data(rva=rva, length=length)
            if data != b'\x00' * length:
                return data
        return None


    @classmethod
    def _get_parsed_pe_files(cls, context, config, config_path, vad, extensions):
        file_handle = None
        pe_file = None
        for mem_obj, ext, file_handle in cls._get_file_hnd_from_dumpfiles(
                context, config, config_path, vad, extensions=extensions):

            file_handle.seek(0)
            try:
                pe_file = pefile.PE(data=file_handle.read(), fast_load=True)
            except Exception as exp:
                vollog.warning("Unable to load Image file for VAD {:s} "
                               "with pefile."
                               .format(vad.get_file_name()))
                continue
            file_handle.seek(0)
            yield [mem_obj, ext, file_handle, pe_file]

