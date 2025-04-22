#  Simple plugin to enumerate and analyze all _MMPTE_SOFTWARE PTEs for swapped pages
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


"""Simple plugin to enumerate and analyze all _MMPTE_SOFTWARE PTEs for swapped
pages.

References:
https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/ 
"""
import logging
from volatility3.framework import interfaces, renderers, constants
from volatility3.plugins.windows import pslist, ptenum
from volatility3.framework.configuration import requirements

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
                                                  architectures = ["Intel32", "Intel64"]),
                   requirements.SymbolTableRequirement(name = "nt_symbols",
                                                       description = "Windows kernel symbols")]
else:
    # The highest major version we currently support is 2.
    raise RuntimeError(f"Framework interface version {framework_version} is "
                        "currently not supported.")


class SwapEnumerator(interfaces.plugins.PluginInterface, ptenum.PteEnumerator):
    """Simple plugin to enumerate and analyze all _MMPTE_SOFTWARE PTEs for
    swapped pages."""
    _required_framework_version = (framework_version, 0, 0)
    _version = (0, 9, 0)

    @classmethod
    def get_requirements(cls):
        return [*kernel_reqs,
                requirements.PluginRequirement(name = 'pslist',
                                               plugin = pslist.PsList,
                                               version = (3, 0, 0)),
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
                                            default = None,
                                            optional = True),
                requirements.IntRequirement(name = 'swap_offset',
                                            description = "Swap offset to focus on.",
                                            default=None,
                                            optional = True),
                requirements.IntRequirement(name = 'pagefile_idx',
                                            description = "A specific pagefile idx to filter for.",
                                            default=None,
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

        return renderers.TreeGrid([("Enumerated Pages", int),
                                   ("Swap PTE count", int),
                                   ("Pagefile IDX count", str),
                                   ("Swap offset top 20", str),
                                   ("Bit count for PageFileHigh", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          self.context,
                                          kernel_module_name=self.config["kernel"],
                                          filter_func = filter_func)))


    def _generator(self, procs):

        i_proc = 0
        processes = list(procs)
        len_procs = len(processes)
        all_pages = 0
        swap_offset_dict = dict()
        pagefile_idx_dict = dict()
        bit_counter = dict()
        bit_range = 32
        matching_pages = 0
        self._initialize_internals()
        for i in range(bit_range):
            bit = 1 << (i + self._PAGE_BITS)
            bit_counter[i] = {'bit': bit, 1: 0, 0: 0}
        for proc in processes:
            i_proc += 1
            self.init_for_proc(proc)
            self._ensure_mmpfn_db_raw()
            pid = int(proc.UniqueProcessId)
            self._progress_callback(
                (i_proc/len_procs) * 100,
                "Enumerating page tables for Process {:d}".format(pid))
            
            for pte_run in self.enumerate_ptes(start=self.config.get('start'), 
                                               end=self.config.get('end'),
                                               nx_ret=self.config.get('check_exec', False),
                                               zero_ret=True):
                all_pages += 1

                if pte_run.state != 'SOFT':
                    continue
                
                if self.config["swap_offset"] is not None and \
                        pte_run._swap_offset != self.config["swap_offset"]:
                    continue

                if self.config["pagefile_idx"] is not None and \
                        pte_run._pagefile_idx != self.config["pagefile_idx"]:
                    continue

                matching_pages += 1
                if pte_run._swap_offset is None:
                    swap_offset = -1
                else:
                    swap_offset = pte_run._swap_offset

                if swap_offset in swap_offset_dict:
                    swap_offset_dict[swap_offset] += 1
                else:
                    swap_offset_dict[swap_offset] = 1

                if pte_run._pagefile_idx in pagefile_idx_dict:
                    pagefile_idx_dict[pte_run._pagefile_idx] += 1
                else:
                    pagefile_idx_dict[pte_run._pagefile_idx] = 1

                if swap_offset == -1:
                    continue

                for i, values in bit_counter.items():
                    if swap_offset & values['bit']:
                        values[1] += 1
                    else:
                        values[0] += 1 

        self._release_mmpfn_db_raw()
        vollog.info("Enumerated {:d} pages\n".format(all_pages))

        pagefile_idx_dict = sorted(pagefile_idx_dict.items(), key=lambda item: item[1])
        swap_offset_dict = sorted(swap_offset_dict.items(), key=lambda item: item[1])

        pagefile_idx_result = "\n\n"
        for idx, count in pagefile_idx_dict:
            pagefile_idx_result += "idx count for {:d}: {:d}\n".format(idx, count)

        bit_count_result = "\n"
        if swap_offset_dict:
            for i, values in bit_counter.items():
                bit_count_result += "bit {:d}: {:d} set, {:d} unset.\n".format(i, values[1], values[0])

        swap_offset_result = "\n"
        # Getting the top 20 swap offsets
        for i in range(min(len(swap_offset_dict), 20)):
            swap_offset, count = swap_offset_dict.pop()
            if swap_offset == -1:
                continue
            swap_offset_result += "offset count for 0x{:x}: {:d}\n".format(swap_offset, count)

        yield (0, (all_pages, matching_pages, pagefile_idx_result, swap_offset_result, bit_count_result))

