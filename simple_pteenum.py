#  Simple plugin to enumerate PTEs.
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


"""Simple plugin to enumerate PTEs.

References:
https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/
"""
import logging, textwrap
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


class SimplePteEnumerator(interfaces.plugins.PluginInterface, ptenum.PteEnumerator):
    """Simple plugin to enumerate PTEs."""
    _required_framework_version = (framework_version, 0, 0)
    _version = (0, 9, 0)

    @classmethod
    def get_requirements(cls):
        return [*kernel_reqs,
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
                                            default = None,
                                            optional = True),
                requirements.BooleanRequirement(name = 'include_image_files',
                                            description = "Also include pages belonging to mapped image files (data files are included by default).",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'include_demand_zero',
                                            description = "Include PTEs that have yet no corresponding page. This will also include \"PTEs\" that not yet have any valid vaddr, but a valid Page Table, and might lead to Warnings/False Positives if not dealt with accordingly.",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'include_only_exec',
                                            description = "Only include executable pages.",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'check_valid',
                                            description = "Only include valid pages.",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'check_proto',
                                            description = "Only include Prototype PTEs.",
                                            default = False,
                                            optional = True),
                requirements.BooleanRequirement(name = 'print_pages',
                                            description = "Print all matching pages.",
                                            default = False,
                                            optional = True),]


    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        if framework_version == 1:
            layer_name = self.config[kernel_layer_name]
            symbol_table = self.config['nt_symbols']
        else:
            kernel = self.context.modules[self.config[kernel_layer_name]]
            layer_name = kernel.layer_name
            symbol_table = kernel.symbol_table_name

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Matching pages", int),
                                   ("Printed PteRun", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          self.context,
                                          layer_name = layer_name,
                                          symbol_table = symbol_table,
                                          filter_func = filter_func)))


    def _generator(self, procs):
        i_proc = 0
        processes = list(procs)
        len_procs = len(processes)
        self._initialize_internals()
        # If enumerating thousands of PTEs, use this and its corresponding
        # function _release_mmpfn_db_raw at the bottom. It will speed things
        # up.
        self._ensure_mmpfn_db_raw()

        for proc in processes:
            i_proc += 1
            additional_output = "-"
            self.init_for_proc(proc)
            self._progress_callback(
                (i_proc/len_procs) * 100,
                "Enumerating page tables for Process {:d}".format(self.pid))

            zero_ret = not self.config.get('include_demand_zero')
            ptes_per_proc = 0
            matching_ptes = 0
            for pte_run in self.enumerate_ptes(start=self.config.get('start'), 
                                               end=self.config.get('end'),
                                               nx_ret=self.config.get('include_only_exec'),
                                               zero_ret=zero_ret):
                ptes_per_proc += 1
                if self.config.get('check_valid') and pte_run.state != 'HARD':
                    continue
                if self.config.get('check_proto') and not pte_run.is_proto:
                    continue
                    
                matching_ptes += 1

                if self.config.get('print_pages'):
                    additional_output = "\n\n"
                    additional_output += pte_run.get_full_string_repr()
                    yield (0, (self.pid, self.proc_name, matching_ptes, additional_output))
            
            if not self.config.get('print_pages'):
                yield (0, (self.pid, self.proc_name, matching_ptes, additional_output))

        self._release_mmpfn_db_raw() 
