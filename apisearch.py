#  This plugin helps identifying pointers to APIs (functions defined in loaded DLLs).
#
#    Copyright (c) 2021, Frank Block, <coding@f-block.org>
#
#       All rights reserved.
#
#       Redistribution and use in source and binary forms, with or without modification,
#       are permitted provided that the following conditions are met:
#
#       * Redistributions of source code must retain the above copyright notice, this
#         list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above copyright notice,
#         this list of conditions and the following disclaimer in the documentation
#         and/or other materials provided with the distribution.
#       * The names of the contributors may not be used to endorse or promote products
#         derived from this software without specific prior written permission.
#
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


"""This plugin helps identifying pointers to APIs (functions defined in loaded
DLLs). It does that by iterating over all loaded DLLs, enumerating their exports
and searching for any pointers to the exported functions. 

References:
https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/
"""

import logging, pefile
from tempfile import SpooledTemporaryFile
from typing import Callable, List, Generator, Iterable, Type, Optional
from volatility3.plugins.windows import dumpfiles, dlllist, pslist
from volatility3.plugins.windows.ptemalfind import PteMalfindInterface
from volatility3.framework import renderers, interfaces, exceptions, constants
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners
from volatility3.framework.interfaces.objects import ObjectInterface
from volatility3.framework.interfaces.layers import ScannerInterface

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
    kernel_reqs = [requirements.ModuleRequirement(name = kernel_layer_name, description = 'Windows kernel',
                                                architectures = ["Intel32", "Intel64"])]
else:
    # The highest major version we currently support is 2.
    raise RuntimeError(f"Framework interface version {framework_version} is "
                        "currently not supported.")


class ImportExportParser:
    """Offers functions to parse imports/exports of given DLLs."""

    @staticmethod
    def open_method(filename):
        """Helper function to be able to use Vol3's dumping functions."""
        obj = SpooledTemporaryFile(mode='wb')
        obj.preferred_filename = 'img'
        return obj


    # TODO finish implementation
    # Currently not used;
    # Reimplementation of load_order_modules, that also supports WOW64 processes
    def load_order_modules(cls, proc) -> Iterable[interfaces.objects.ObjectInterface]:
        """Generator for DLLs in the order that they were loaded."""

        try:
            peb = proc.get_peb()
            for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                    f"{self.get_symbol_table_name()}{constants.BANG}_LDR_DATA_TABLE_ENTRY",
                    "InLoadOrderLinks"):
                yield entry
            if proc.get_is_wow64():
                peb = proc.WoW64Process.Peb
                print(peb)
        except exceptions.InvalidAddressException:
            return


    @staticmethod
    def get_imports(file_handle, dll_entry):
        """Parses the Imports of a given DLL, contained in file_handle.

        Returns:
            A dict containing each API address with its import object.
            {api1_offset: [dll_entry, imp_obj], api2_offset: ...}
        """
        import_dict = dict()
        if not file_handle or not dll_entry:
            return import_dict

        file_handle.seek(0)
        try:
            pe_file = pefile.PE(data=file_handle.read())
        except:
            return import_dict

        try:
            for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_dict[imp.address.to_bytes(8, 'little')] = [dll_entry, imp]
        except AttributeError:
            pass

        return import_dict


    @staticmethod
    def get_exports(file_handle, dll_entry, img_base=None):
        """Parses the Exports of a given DLL, contained in file_handle.

        Returns:
            A dict containing each API address with its export object.
            {api1_offset: [dll_entry, exp_obj], api2_offset: ...}
        """
        export_dict = dict()
        if not file_handle or not dll_entry:
            return export_dict

        file_handle.seek(0)
        try:
            pe_file = pefile.PE(data=file_handle.read())
        except:
            return export_dict

        if img_base is None:
            img_base = pe_file.OPTIONAL_HEADER.ImageBase

        try:
            for exp in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                # TODO support also 32 bit processes/addresses
                export_dict[(img_base + exp.address).to_bytes(8, 'little')] = [dll_entry, exp]

        except AttributeError:
            pass

        return export_dict


    @classmethod
    def _get_file_hnd_from_dumpfiles(cls, context, config, config_path, vad, extensions=['dat', 'img']):
        """Yields a file handle for each available DataSectionObject and
        ImageSectionObject file object."""
        dump_parameters = []
        file_obj = None
        vad_start = vad.get_start()

        if not vad.has_member("Subsection"):
            return

        memory_layer = context.layers['memory_layer']

        try:
            file_obj = vad.Subsection.ControlArea.FilePointer.dereference().cast("_FILE_OBJECT")
        except exceptions.InvalidAddressException:
            return

        if not file_obj or not file_obj.is_valid():
            return

        for member_name, extension in [("DataSectionObject", "dat"), ("ImageSectionObject", "img")]:
            if extension not in extensions:
                continue
            try:
                section_obj = getattr(file_obj.SectionObjectPointer, member_name)
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                if control_area.is_valid():
                    dump_parameters.append((control_area, memory_layer, extension))
            except exceptions.InvalidAddressException:
                pass
        for memory_object, layer, extension in dump_parameters:
            file_handle = dumpfiles.DumpFiles.dump_file_producer(file_obj, memory_object, cls.open_method, layer, '')
            if file_handle:
                yield file_handle


    @classmethod
    def get_exports_from_dumpfiles(cls, context, config, config_path, vad, dll_entry):
        """Parses the DLL from the img/dat representations of the
        associated file, if available.
        
        Returns:
            See get_exports function."""
        export_dict = dict()

        for file_handle in cls._get_file_hnd_from_dumpfiles(context, config, config_path, vad):
            export_dict.update(cls.get_exports(file_handle, dll_entry, img_base=vad.get_start()))

        return export_dict


    @classmethod
    def get_imports_from_dumpfiles(cls, context, config, config_path, vad, dll_entry):
        """Parses the DLL from the img/dat representations of the
        associated file, if available.
        
        Returns:
            See get_imports function."""
        import_dict = dict()

        for file_handle in cls._get_file_hnd_from_dumpfiles(context, config, config_path, vad, extensions=['img']):
            import_dict.update(cls.get_imports(file_handle, dll_entry))

        return import_dict


    @classmethod
    def get_exports_from_file_objs_old(cls, context, config, config_path, vad, dll_entry):
        """Parses the DLL from the img/dat representations of the
        associated file, if available.
        
        Returns:
            See get_exports function."""
        dump_parameters = []
        file_obj = None
        export_dict = dict()
        vad_start = vad.get_start()

        if not vad.has_member("Subsection"):
            return export_dict

        memory_layer = context.layers['memory_layer']

        try:
            file_obj = vad.Subsection.ControlArea.FilePointer.dereference().cast("_FILE_OBJECT")
        except exceptions.InvalidAddressException:
            return export_dict

        if not file_obj or not file_obj.is_valid():
            return export_dict

        for member_name, extension in [("DataSectionObject", "dat"), ("ImageSectionObject", "img")]:
            try:
                section_obj = getattr(file_obj.SectionObjectPointer, member_name)
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                if control_area.is_valid():
                    dump_parameters.append((control_area, memory_layer, extension))
            except exceptions.InvalidAddressException:
                pass
        for memory_object, layer, extension in dump_parameters:
            file_handle = dumpfiles.DumpFiles.dump_file_producer(file_obj, memory_object, cls.open_method, layer, '')
            if file_handle:
                export_dict.update(cls.get_exports(file_handle, dll_entry, img_base=vad_start))

        return export_dict


    @classmethod
    def _get_file_hnd_from_vad(cls, context, config, config_path, dll_entry, proc_layer):
        """Returns:
            A file handle, containing the DLL's content."""

        # dump_pe from VAD (represented by an element of the InLoadOrderModuleList)
        pe_table_name = intermed.IntermediateSymbolTable.create(context,
                                                                config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)
        return dlllist.DllList.dump_pe(context, pe_table_name, dll_entry, cls.open_method, proc_layer)


    @classmethod
    def get_exports_from_vad(cls, context, config, config_path, vad, dll_entry, proc_layer):
        """Parses the DLL from the given VAD and returns the Exports. This
        function uses only the VAD's content itself, but not the
        img/vacb/dat representations of the associated file.
        
        Returns:
            See get_exports function."""

        # dump_pe from VAD (represented by an element of the InLoadOrderModuleList)
        file_handle = cls._get_file_hnd_from_vad(context, config, config_path, dll_entry, proc_layer)
        return cls.get_exports(file_handle, dll_entry, img_base=vad.get_start())


    @classmethod
    def get_imports_from_vad(cls, context, config, config_path, vad, dll_entry, proc_layer):
        """Parses the DLL from the given VAD and returns the Exports. This
        function uses only the VAD's content itself, but not the
        img/vacb/dat representations of the associated file.
        
        Returns:
            See get_imports function."""

        # dump_pe from VAD (represented by an element of the InLoadOrderModuleList)
        file_handle = cls._get_file_hnd_from_vad(context, config, config_path, dll_entry, proc_layer)
        return cls.get_imports(file_handle, dll_entry)


    @classmethod
    def get_exports_from_vad_old(cls, context, config, config_path, vad, dll_entry, proc_layer):
        """Parses the DLL from the given VAD and returns the Exports. This
        function uses only the VAD's content itself, but not the
        img/vacb/dat representations of the associated file.
        
        Returns:
            See get_exports function."""
        vad_start = vad.get_start()

        # dump_pe from VAD (represented by an element of the InLoadOrderModuleList)
        pe_table_name = intermed.IntermediateSymbolTable.create(context,
                                                                config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)
        file_handle = dlllist.DllList.dump_pe(context, pe_table_name, dll_entry, cls.open_method, proc_layer)
        return cls.get_exports(file_handle, dll_entry, img_base=vad_start)


    @classmethod
    def get_exports_from_dll(cls, context, config, config_path, vad, dll_entry, proc_layer):
        """Parses the DLL from the given VAD and returns the Exports. This
        function not only uses the VAD's content itself, but also the
        img/vacb/dat representations of the associated file, if available, for
        the cases where the VAD's content is unavailable (e.g., paged out).
        
        Returns:
            See get_exports function."""
        export_dict = dict()
        export_dict.update(cls.get_exports_from_dumpfiles(context, config, config_path, vad, dll_entry))
        export_dict.update(cls.get_exports_from_vad(context, config, config_path, vad, dll_entry, proc_layer))
        return export_dict


    @classmethod
    def get_exports_for_proc(cls, proc, context, config, config_path, progress_callback=None, vadlist2=None, load_order_modules=None):
        """
        
        Returns:
            See get_exports function."""
        if not vadlist2:
            vadlist2 = list(proc.get_vad_root().traverse())
        vadlist=list()
        export_dict = dict()
        dll_offset_dict = dict()
        proc_layer_name = proc.add_process_layer()
        pid = proc.UniqueProcessId
        vads = list(proc.get_vad_root().traverse())
        if not vads:
            return export_dict
        # TODO keep list of already parsed dumpfiles exports
        dll_entries = list(proc.load_order_modules())
        for dll_entry in proc.load_order_modules():
            dll_offset_dict[dll_entry.DllBase] = dll_entry
        for i, vad in enumerate(vads):
            vad_start = vad.get_start()
            vadlist.append((vad_start, vad.get_end(), vad))
            if vad_start not in dll_offset_dict.keys():
                continue
            if progress_callback:
                progress_callback(
                    (i/len(vads)) * 100,
                    "{:s}: Getting exports from DLLs for Process {:d}"
                    .format(cls.__name__, pid))
            # TODO use multithreading
            export_dict.update(cls.get_exports_from_dll(context,
                                                        config,
                                                        config_path,
                                                        vad,
                                                        dll_offset_dict[vad_start],
                                                        proc_layer_name))
        return export_dict


# TODO make more efficient; e.g., store already parsed img/dat files
class ApiScanner(ScannerInterface, PteMalfindInterface):
    """This scanner helps identifying pointers to APIs (functions defined in
    loaded DLLs). It does that by iterating over all loaded DLLs, enumerating
    their exports and searching for any pointers to the exported functions. 

    References:
    """
    thread_safe = True

    def __init__(self, proc: ObjectInterface = None, context=None, config=None, config_path=None, progress_callback=None):
        ScannerInterface.__init__(self)
        self._proc = proc
        self._context = context
        self.export_dict = ImportExportParser.get_exports_for_proc(proc, context, config, config_path, progress_callback=progress_callback)
        self._subscanner = scanners.MultiStringScanner(
            [x for x in self.export_dict.keys()])


    def __call__(self, data: bytes, data_offset: int):
        for offset, pattern in self._subscanner(data, data_offset):
            yield (offset, self.export_dict[pattern])


    def get_parsed_results(self, hits):
        """Parses the search results"""
        if not hits or len(hits) <= 0:
            return None

        last_offset = 0
        for offset, data in sorted(hits):
            dll_entry, export = data
            try:
                mod_name = dll_entry.BaseDllName.get_string()
            except:
                mod_name = hex(dll_entry.DllBase)
            exp_name = (export.name or export.ordinal)
            exp_name = "ordinal: {:d}".format(exp_name) if isinstance(exp_name, int) else exp_name.decode('utf-8')
            exp_name = mod_name + '!' + exp_name
            # TODO adjust when support for 32 bit is added
            distance = 0 if last_offset == 0 else offset - last_offset - 8
            yield((offset, exp_name, distance))
            last_offset = offset


    def get_formatted_results(self, hits, vad=None) -> Generator[str, None, None]:
        """Generator for pretty-printable results."""
        if not hits:
            return
        hits = list(hits)
        if len(hits) <= 0:
            return
        
        indent = ""
        if vad:
            yield("Hits in VAD at 0x{:x}:".format(vad.get_start()))
            indent = "    "
        for offset, exp_name, distance in self.get_parsed_results(hits):
            yield("0x{:x}: {:s}    distance: {:d}".format(offset, exp_name, distance))


    def get_ptemalfind_results(self, hits, **kwargs) -> str:
        return "\n".join(self.get_formatted_results(hits))


class ApiSearch(interfaces.plugins.PluginInterface, PteMalfindInterface):
    """This plugin helps identifying pointers to APIs (functions defined in
    loaded DLLs). It does that by iterating over all loaded DLLs, enumerating
    their exports and searching for any pointers to the exported functions. 

    References:
    """

    _required_framework_version = (framework_version, 0, 0)
    _version = (1, 0, 0)
    # 4 GB
    MAXSIZE_DEFAULT = 0x100000000

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [*kernel_reqs,
                requirements.ListRequirement(name = 'pid',
                                             description = 'Filter on specific process IDs',
                                             element_type = int,
                                             optional = True),
                requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
                requirements.IntRequirement(name = 'address',
                                            description = "A VAD's virtual start address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the VAD's range.",
                                            default=None,
                                            optional = True),
                requirements.IntRequirement(name = 'maxsize',
                                            description = ("Only VADs with a size <= maxsize will be scanned. "
                                                          f"default: 0x{cls.MAXSIZE_DEFAULT:x}"),
                                            default = cls.MAXSIZE_DEFAULT,
                                            optional = True),
                requirements.BooleanRequirement(name = 'scan_dlls',
                                            description = ("This will also scan loaded DLLs for any references to APIs. "
                                                           "CAUTION: This will return a lot of results. The 'address' "
                                                           "argument is usually the better option."),
                                            default = False,
                                            optional = True)]


    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        if framework_version == 1:
            layer_name = self.config[kernel_layer_name]
            symbol_table = self.config['nt_symbols']
        else:
            kernel = self.context.modules[self.config[kernel_layer_name]]
            layer_name = kernel.layer_name
            symbol_table = kernel.symbol_table_name

        return renderers.TreeGrid([("PID", int), ("Process", str), ("VAD Start", format_hints.Hex),
                                   ("Hit Addr", format_hints.Hex), ("API", str), ("Distance", int)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = layer_name,
                                          symbol_table = symbol_table,
                                          filter_func = filter_func)))


    @classmethod
    def get_results_for_proc(cls, context, config, config_path, proc, api_scanner, maxsize=None, scan_dlls=False):
        """Searches all matching VADs of the given process for any API
        pointers (taken from the exports of this processes' DLLs)."""
        vadlist = list()
        dll_offset_list = list()
        dll_entries = None
        if maxsize is None:
            maxsize = cls.MAXSIZE_DEFAULT
        proc_layer_name = proc.add_process_layer()
        proc_layer = context.layers[proc_layer_name]

        if not scan_dlls:
            dll_entries = list(proc.load_order_modules())
            for dll_entry in proc.load_order_modules():
                dll_offset_list.append(dll_entry.DllBase)
        dll_offset_list = sorted(dll_offset_list)

        # Generating sections-list to scan
        sections = list()
        for vad in proc.get_vad_root().traverse():
            vad_start = vad.get_start()
            if not scan_dlls and vad_start in dll_offset_list:
                continue
            vad_end = vad.get_end()
            vad_size = vad_end - vad_start
            if vad_size > maxsize:
                continue
            sections.append((vad_start, vad_size))

            vadlist.append((vad_start, vad_end, vad))

        hits = list(proc_layer.scan(context=context, scanner=api_scanner, sections=sections))

        # Correlating hits with VADs. We are doing this to be able to start
        # the scanner with all sections at once, which should increase
        # performance due to threading (if enabled).
        vad_hits = list()
        hits = sorted(hits)
        # We are popping from vadlist, so reverse order
        vadlist = sorted(vadlist, reverse=True)
        
        vad_start, vad_end, vad = vadlist.pop()
        for offset, data in hits:
            while not (vad_start <= offset < vad_end):
                # We're moving to the next VAD. If there are results for the
                # current one, we return them now.
                if vad_hits:
                    yield (vad, vad_hits)
                    vad_hits = list()
                vad_start, vad_end, vad = vadlist.pop()
            
            vad_hits.append((offset, data))

        if vad_hits:
            yield (vad, vad_hits)


    @classmethod
    def get_results_for_sections(cls, context, config, config_path, proc, sections, progress_callback=None):
        """Searches the given process within the given sections for any API
        pointers (taken from the exports of this processes' DLLs)."""
        api_scanner = ApiScanner(proc=proc, context=context, config=config, config_path=config_path, progress_callback=progress_callback)
        proc_layer_name = proc.add_process_layer()
        proc_layer = context.layers[proc_layer_name]
        hits = list(proc_layer.scan(context=context, scanner=api_scanner, sections=sections))
        return (api_scanner, hits)


    @classmethod
    def get_formatted_results(cls, api_scanner, hits) -> Generator[str, None, None]:
        """Pretty-printed results with resolved export names."""
        return api_scanner.get_formatted_results(hits)


    @classmethod
    def get_ptemalfind_results(cls, context=None, config=None, config_path=None, proc=None, sections=None, progress_callback=None, **kwargs) -> str:
        """Pretty-printed results with resolved export names dedicated to be
        used from within the PteMalfind plugin."""
        api_scanner, hits = cls.get_results_for_sections(context, config, config_path, proc, sections, progress_callback=progress_callback)
        return api_scanner.get_ptemalfind_results(hits)


    def _generator(self, procs):
        processes = list(procs)
        len_procs = len(processes)
        progress_callback = None
        if len_procs == 1:
            progress_callback = self._progress_callback

        for i, proc in enumerate(processes):
            pid = proc.UniqueProcessId
            proc_name = utility.array_to_string(proc.ImageFileName)
            if len_procs > 1: 
                self._progress_callback(
                    (i/len_procs) * 100,
                    "{:s}: Getting exports from DLLs for Process {:d} {:s}"
                    .format(self.__class__.__name__, pid, proc_name))
            
            if self.config['address']:
                vad = None
                vad_start = None
                sections = None
                for vad in proc.get_vad_root().traverse():
                    vad_start = vad.get_start()
                    if vad_start == self.config['address']:
                        sections = [(vad_start, vad.get_end() - vad_start)]
                        break

                if not sections:
                    vollog.warning("No VAD found for the given address: "
                                   "0x{:x}".format(self.config['address']))
                    return

                api_scanner, hits = self.get_results_for_sections(self.context, self.config, self.config_path, proc, sections, progress_callback=progress_callback)
                for offset, exp_name, distance in api_scanner.get_parsed_results(hits):
                    yield(0, (pid, proc_name, format_hints.Hex(vad_start), format_hints.Hex(offset), exp_name, distance))

            else:
                api_scanner = ApiScanner(proc=proc, context=self.context, config=self.config, config_path=self.config_path, progress_callback=progress_callback)
                for vad, hits in self.get_results_for_proc(self.context, self.config, self.config_path, proc, api_scanner, maxsize=self.config['maxsize'], scan_dlls=self.config['scan_dlls']):
                    for offset, exp_name, distance in api_scanner.get_parsed_results(hits):
                        yield(0, (pid, proc_name, format_hints.Hex(vad.get_start()), format_hints.Hex(offset), exp_name, distance))
