#  This plugin reveals all executable pages by examining PTEs
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


"""This plugin enumerates and analyzes all PTEs for a given process and
can e.g. identify executable pages in VADs, initialized without an
executable protection. It furthermore allows to reveal executable and modified
pages within mapped image files.

References:
https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/
https://github.com/f-block/DFRWS-USA-2019
https://dfrws.org/presentation/windows-memory-forensics-detecting-unintentionally-hidden-injected-code-by-examining-page-table-entries/
"""

import logging, importlib, textwrap
from abc import ABCMeta, abstractmethod
from typing import Dict, Tuple, Generator, List, Type, Optional

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo
from volatility3.plugins.windows.ptenum import PteEnumerator, PteRun
from volatility3.framework.interfaces.objects import ObjectInterface

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


class PteMalfindInterface(metaclass = ABCMeta):
    """Each plugin/scanner invokable from PteMalfind must implement this
    interface."""

    @abstractmethod
    def get_ptemalfind_results(self, *args, **kwargs) -> str:
        """This function will be called from within PteMalfind and expects
        a string analysis-result."""

    @classmethod
    def __subclasshook__(cls, subclass):
        return hasattr(subclass, 'get_ptemalfind_results') and \
               callable(subclass.get_ptemalfind_results)


class PteMalfind(interfaces.plugins.PluginInterface):
    """This plugin enumerates and analyzes all PTEs for a given process and
    can e.g. identify executable pages in VADs, initialized without an
    executable protection. It furthermore allows to reveal executable and
    modified pages within mapped image files.

    References:
    https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/
    https://github.com/f-block/DFRWS-USA-2019
    https://dfrws.org/presentation/windows-memory-forensics-detecting-unintentionally-hidden-injected-code-by-examining-page-table-entries/
    """

    _required_framework_version = (framework_version, 0, 0)
    _version = (0, 9, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [*kernel_reqs,
                requirements.BooleanRequirement(name = "dump",
                                                description = "Dumps the executable memory regions to files.",
                                                default = False,
                                                optional = True),
                requirements.PluginRequirement(name = 'pslist',
                                               plugin = pslist.PsList,
                                               version = (2, 0, 0)),
                requirements.ListRequirement(name = 'pid',
                                            element_type = int,
                                            description = "Process ID to include (all other processes are excluded)",
                                            optional = True),
                requirements.IntRequirement(name = 'start',
                                            description = "The lowest address to examine; default=0",
                                            default=0,
                                            optional = True),
                requirements.IntRequirement(name = 'end',
                                            description = "Upper limit address to examine; default: highest usermode address",
                                            default=None,
                                            optional = True),
                requirements.BooleanRequirement(name = 'include_image_files',
                                            description = "Also print modified executable pages belonging to mapped files (e.g. the result of hooking).",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'only_image_files',
                                            description = "Only print modified executable pages belonging to mapped files (e.g. the result of hooking).",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'dump_only_xpages',
                                            description = "Only the executable pages themselves are part of the dump; default is the whole VAD content.",
                                            default = False,
                                            optional = True),
                requirements.ListRequirement(name = 'scanners',
                                            element_type = str,
                                            description = "Additional scanners to invoke on identified executable memory.",
                                            optional = True),
                requirements.ListRequirement(name = 'plugins',
                                            element_type = str,
                                            description = "Additional plugins to invoke on identified executable memory.",
                                            optional = True),
                requirements.BooleanRequirement(name = 'sp_only_xpages',
                                            description = "Run additional scanners/plugins only on the executable pages; default is the whole VAD content.",
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

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start Addr", format_hints.Hex),
                                   ("End Addr", format_hints.Hex), ("Protection", str),
                                   ("Type", str), ("File output", str),
                                   ("Details", str), ("Hexdump", format_hints.HexBytes), 
                                   ("Disasm", interfaces.renderers.Disassembly),
                                   ("Extension(s)", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = layer_name,
                                          symbol_table = symbol_table,
                                          filter_func = filter_func)))


    @staticmethod
    def get_vad_filename(vad):
        try:
            vad_name = vad.get_file_name()
            if not isinstance(vad_name, str):
                return "N/A"
            return vad_name
        except Exception:
            return "N/A"


    @classmethod
    def get_page_result_for_render(
            cls,
            vad: ObjectInterface,
            xpages: List[PteRun],
            ptenum: PteEnumerator,
            config: interfaces.configuration.HierarchicalDict,
            open_method: Type[interfaces.plugins.FileHandlerInterface],
            ext_output: str):
        """This method takes the result of get_ptemalfind_data and returns
        a human readable output according to the TreeGrid definition in the run
        function."""
        meta_info = ""
        sorted_pages = sorted(xpages, key=lambda x: x.vaddr)
        
        # The first (sorted by VADDR) executable page for this VAD.
        first_page = sorted_pages[0]
        
        # Points to the beginning of the containing memory area, disregarding
        # any leading non-executable or empty pages. For lonely pages (not
        # belonging to any VAD), each page is its own memory area.
        memory_area_start = first_page.vaddr if type(vad) == int else \
            vad.get_start()

        # first_printable_page is the first page in the given list of
        # executable pages that also accessible and "printworthy" (not solely
        # null bytes) content. This function expects in-memory pages with only
        # null bytes being already stripped, so right now we simply search
        # the first executable page with any in-memory data (skipping paged
        # out pages).
        first_printable_page = first_page
        tmp_idx = 1
        while not first_printable_page.is_data_available and \
                tmp_idx < len(sorted_pages):
            first_printable_page = sorted_pages[tmp_idx]
            tmp_idx += 1

        # The total amount of bytes within all executable pages for this VAD.
        total_phys_bytes = sum([x.length for x in xpages])

        memory_area_end = 0
        if type(vad) == int:
            file_mem_type_str = 'page'
            memory_area_end = \
                memory_area_start + first_printable_page.length - 1
            mem_protection_str = 'executable'
            mem_type_str = 'orphaned page'
            meta_info += (
                "The page at {0} with a size of {1} bytes is executable but "
                "not related to any known VAD. This can, but does not have to "
                "be suspicious.\n".format(
                hex(first_printable_page.vaddr),
                hex(first_printable_page.length)))

            if not first_printable_page.is_data_available:
                meta_info += (
                    "The page is not available from the memory dump (e.g. "
                    "because it has been paged out). So there is nothing to "
                    "dump/disassemble here.\n")

        else:
            file_mem_type_str = 'vad'
            memory_area_end = vad.get_end()
            mem_protection_str = vad.get_protection(
                vadinfo.VadInfo.protect_values(ptenum.context,
                                               ptenum.kernel.layer_name,
                                               ptenum.kernel.symbol_table_name),
                vadinfo.winnt_protections)

            if vad.get_private_memory() > 0:
                mem_type_str = 'Private Memory'
            elif ptenum.vad_contains_image_file(vad):
                mem_type_str = 'Mapped Image File: ' + cls.get_vad_filename(vad)
            elif ptenum.vad_contains_data_file(vad):
                mem_type_str = 'Mapped Data File: ' + cls.get_vad_filename(vad)
            else:
                mem_type_str = 'Mapped Memory'

            meta_info += (
                "{0} non empty page(s) (starting at {1}) with a total size of "
                "{2} bytes in this VAD were executable (and for mapped image "
                "files also modified).\n".format(len(xpages),
                                                 hex(first_page.vaddr),
                                                 hex(total_phys_bytes)))

            # The following lines simply check for any skipped bytes in relation
            # to a potentially given start address.
            # Skipped bytes in the sense of: If the first executable page is not
            # at the beginning of the VAD, the diff are the skipped bytes.
            ptenum.PAGE_BITS = ptenum.kernel_layer._page_size_in_bits
            ptenum.PAGE_SIZE = 1 << ptenum.PAGE_BITS
            ptenum.PAGE_BITS_MASK = ptenum.PAGE_SIZE - 1
            start_arg = config.get('start', None) 
            first_byte = start_arg &~ ptenum.PAGE_BITS_MASK \
                         if (start_arg and start_arg > memory_area_start) \
                         else memory_area_start
            skipped_bytes = int(first_page.vaddr - first_byte)

            if not first_printable_page.is_data_available:
                meta_info += (
                    "Seems like all executable pages from this VAD are not "
                    "available from the memory dump (e.g. because they have "
                    "been paged out). So there is nothing to dump/disassemble "
                    "here.\n")

            else:
                if skipped_bytes:
                    meta_info += (
                        "Skipping the first {0} bytes, as they are either not "
                        "modified (only applies for mapped image files), empty,"
                        " not executable or skipped via cmdline argument.\n"
                        .format(hex(skipped_bytes)))
    
                if first_printable_page.vaddr != first_page.vaddr:
                    meta_info += (
                        "We only start printing at {0} as the first {1} "
                        "bytes seem to be not available from the memory dump "
                        "(e.g. because they have been paged out). But the first "
                        "executable page is at {2}.\n".format(
                        hex(first_printable_page.vaddr),
                        hex(first_printable_page.vaddr-first_page.vaddr),
                        hex(first_page.vaddr)))

        if first_printable_page.is_data_available:
            data = first_printable_page.read(length=0x40)
        else:
            data = b''

        disassembler = interfaces.renderers.Disassembly(
            data, first_printable_page.vaddr, ptenum.arch_proc)

        file_output = "Disabled"

        if config['dump']:
            file_output = "Enabled"
            data_filename = "{0}.{1:d}.{2}.0x{3:08x}-0x{4:08x}.dmp".format(
                ptenum.proc_name, ptenum.pid, file_mem_type_str,
                memory_area_start, memory_area_end)
            idx_filename = data_filename[:-3] + 'idx'
            offset = memory_area_start
            chunk_size = 1024 * 1024 * 10

            try:
                data_file_handle = open_method(data_filename)
                idx_file_handle = open_method(idx_filename)
                # write CSV header
                idx_file_handle.write(b"vaddr,file_idx,size,padded\n")

                # correlates index line with offset in dump file
                file_idx = 0
                for page in xpages:
                    x_data = None
                    if not config['dump_only_xpages'] and \
                            page.vaddr > offset:
                        # The rest of the VADs content is not in our range
                        # of executable pages, so we read everything else via
                        # the process layer up until the current exec page.
                        while offset < min(memory_area_end, page.vaddr):
                            to_read = min(chunk_size, page.vaddr - offset)
                            nx_data = ptenum.proc_layer.read(offset,
                                                             to_read,
                                                             pad = True)
                            data_file_handle.write(nx_data)
                            offset += to_read
                    try:
                        x_data = page.read()
                    except:
                        vollog.warning("Exception during read for page data. "
                                       "This shouldn't happen. Process {:d} "
                                       "with vaddr: 0x{:x}"
                                       .format(page.pid, page.vaddr))

                    if not config['dump_only_xpages']:
                        file_idx = page.vaddr - memory_area_start
                    idx_line = \
                        f"0x{page.vaddr:x},0x{file_idx:x},0x{page.length:x},"
                    if config['dump_only_xpages']:
                        file_idx += page.length

                    if x_data:
                        data_file_handle.write(x_data)
                        idx_line += "False"
                    else:
                        data_file_handle.write(b'\x00' * page.length)
                        idx_line += "True"
                    idx_line += "\n"
                    offset += page.length
                    idx_file_handle.write(idx_line.encode('utf-8'))
                
                if not config['dump_only_xpages']:
                    # Writing rest of VAD, after last exec page
                    while offset < memory_area_end:
                        to_read = min(chunk_size, memory_area_end - offset)
                        nx_data = ptenum.proc_layer.read(offset,
                                                         to_read,
                                                         pad = True)
                        if not nx_data:
                            break
                        data_file_handle.write(nx_data)
                        offset += to_read
                data_file_handle.close()
                idx_file_handle.close()
            except Exception as excp:
                vollog.error("Unable to write file {}: {}"
                             .format(data_filename, excp))
                return None

        if meta_info:
            meta_info = "\nMeta Info:\n" + textwrap.indent(meta_info, '    ')

        if ext_output:
            ext_output = "\n\nOutput from extensions:" + textwrap.indent(ext_output, '    ')
        else:
            ext_output = "\n\nOutput from extensions:\n    -"
        ext_output += "\n"
        return (0, (ptenum.pid, ptenum.proc_name, format_hints.Hex(memory_area_start),
                    format_hints.Hex(memory_area_end), mem_protection_str,
                    mem_type_str, file_output, meta_info,
                    format_hints.HexBytes(data), disassembler, ext_output))


    @classmethod
    def get_ptemalfind_data(
            cls,
            procs: Generator[ObjectInterface, None, None],
            context: interfaces.context.ContextInterface,
            config: interfaces.configuration.HierarchicalDict,
            progress_callback: Optional[constants.ProgressCallback],
            start: int = None,
            end: int = None
            ) -> Generator[Tuple[PteEnumerator,
                                 Dict[ObjectInterface, List[PteRun]] ],
                           None, None]:
        """Gathers all executable pages via enumerate_ptes_for_processes
        and strips pages containing only null bytes and unmodified pages
        for mapped image files.
        
        Returns for each process a Tuple containing an instance of the
        PteEnumerator class and a dict with all executable pages for each VAD:
        (PteEnumerator, {vad1: xpages, vad2: xpages, ...})"""
        # used for pages not belonging to any vad
        no_vad_counter = 0

        start_v = start if isinstance(start, int) else config.get('start')
        end_v = end if isinstance(end, int) else config.get('end')        
        # We are iterating PTEs for all processes and check them for being
        # executable.
        for proc, ptenum, pte_runs in \
                PteEnumerator.enumerate_ptes_for_processes(
                    procs,
                    context,
                    config,
                    progress_callback=progress_callback,
                    start=start_v,
                    end=end_v,
                    nx_ret=True,
                    subsec_ret=True,
                    zero_ret=True):

            result = {}
            for pte_run in pte_runs:
                _, _, vad = ptenum.get_vad_for_vaddr(pte_run.vaddr,
                                                     supress_warning=True)
                if not vad:
                    # Each page not belonging to a vad is printed separately.
                    # We are using the no_vad_counter as an index for result.
                    no_vad_counter += 1
                    vad = no_vad_counter

                if vad not in result:
                    result[vad] = [pte_run]
                else:
                    result[vad].append(pte_run)

            proc_result = dict()
            for vad, xpages in result.items():
                if type(vad) == int:
                    vad_contains_imagefile = False
                else:
                    vad_contains_imagefile = ptenum.vad_contains_image_file(vad)

                if (vad_contains_imagefile and not \
                            (config.get('include_image_files') or
                            config.get('only_image_files'))) \
                        or not vad_contains_imagefile and \
                            config.get('only_image_files'):
                    continue

                vad_should_be_printed = False
                drop_these_pages = []
                for pte_run in xpages:
                    if vad_contains_imagefile and pte_run.orig_pte_is_sub_ptr:
                        # We skip unmodified pages for mapped image files
                        # (but still report unmodified executable pages for
                        # mapped data files as this is something suspicious
                        # to look for).
                        drop_these_pages.append(pte_run)
                        continue

                    # We explicitly drop all in-memory pages only containing
                    # null bytes. Previously mapped pages that are currently
                    # unavailable are kept as they could indicate
                    # paged out malicious memory and should be investigated.
                    if pte_run.is_empty:
                        drop_these_pages.append(pte_run)
                        continue

                    vad_should_be_printed = True

                if not vad_should_be_printed:
                    continue

                xpages = [p for p in xpages if p not in drop_these_pages]
                if not xpages:
                    continue

                sorted_pages = sorted(xpages, key=lambda x: x.vaddr)
                proc_result[vad] = xpages

            if proc_result:
                yield (ptenum, proc_result)


    @staticmethod
    def _get_classes(names):
        for name in names:
            try:
                mod_name, class_name = name.split('.')
                mod = __import__('volatility3.plugins.windows.' + mod_name,
                                 fromlist=[class_name])
                tcls = getattr(mod, class_name)
                if not issubclass(tcls, PteMalfindInterface):
                    vollog.warning("The given scanner/plugin {:s} is doesn't "
                                   "use {:s} and hence will not be used."
                                   .format(name, PteMalfindInterface.__name__))
                else:
                    yield tcls
            except Exception as exp:
                vollog.warning("Caught exception while trying to import given "
                               "plugin/scanner {:s}: {:s}"
                               .format(name, str(exp)))


    def _generator(self, procs: Generator[ObjectInterface, None, None]):
        scan_classes = list()
        scan_objs = list()
        plugin_classes = list()
        if self.config.get('scanners'):
            scan_classes = list(self._get_classes(self.config.get('scanners')))
        if self.config.get('plugins'):
            plugin_classes = list(self._get_classes(self.config.get('plugins')))

        for ptenum, proc_result in self.get_ptemalfind_data(procs, self.context, self.config, self._progress_callback):
            for scan_class in scan_classes:
                scan_objs.append(scan_class(proc=ptenum.proc, context=self.context, config=self.config, config_path=self.config_path, progress_callback=self._progress_callback))

            for vad, xpages in proc_result.items():
                ext_output = ""
                if self.config.get('scanners') or self.config.get('plugins'):
                    if self.config.get('sp_only_xpages'):
                        sections = [(x.vaddr, x.length) for x in xpages]
                    else:
                        sections = [(vad.get_start(), vad.get_end() - vad.get_start())]

                for scan_obj in scan_objs:
                    hits = ptenum.proc_layer.scan(context=self.context, scanner=scan_obj, sections=sections)
                    output = scan_obj.get_ptemalfind_results(hits, vad=vad, ptenum=ptenum, proc_result=proc_result)
                    if output:
                        ext_output += "\n"
                        ext_output += "{:s} output:\n".format(scan_obj.__class__.__name__)
                        ext_output += textwrap.indent(output, '    ')
                for plugin_class in plugin_classes:
                    output = plugin_class.get_ptemalfind_results(proc=ptenum.proc, context=self.context, config=self.config, config_path=self.config_path, sections=sections, vad=vad, ptenum=ptenum, proc_result=proc_result, progress_callback=self._progress_callback)
                    if output:
                        ext_output += "\n"
                        ext_output += "{:s} output:\n".format(plugin_class.__name__)
                        ext_output += textwrap.indent(output, '    ')

                yield self.get_page_result_for_render(vad, xpages, ptenum, self.config, self.open, ext_output)
