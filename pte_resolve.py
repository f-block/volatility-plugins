#  This module offers more or less the functionality of WinDbg's pte extension.
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

import logging
from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.plugins.windows import pslist, ptenum
from volatility3.plugins.windows.ptenum import SubsecProtoWrapper
from volatility3.framework.objects import utility
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
    kernel_reqs = [requirements.ModuleRequirement(name = kernel_layer_name, 
                                                  description = 'Windows kernel',
                                                  architectures = ["Intel32", "Intel64"])]
else:
    # The highest major version we currently support is 2.
    raise RuntimeError(f"Framework interface version {framework_version} is "
                        "currently not supported.")


class PteResolve(interfaces.plugins.PluginInterface, ptenum.PteEnumerator):
    """Can be seen as Volatility's implementation of WinDbg's pte extension.
    https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-pte """

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
                requirements.IntRequirement(name = 'vaddr',
                                            description = "A virtual address to resolve",
                                            default=None,
                                            optional = True),
                requirements.IntRequirement(name = 'pte_paddr',
                                            description = "The physical address of a PTE to parse",
                                            default = None,
                                            optional = True),
                requirements.IntRequirement(name = 'pte_vaddr',
                                            description = "The virtual address of a PTE to parse",
                                            default = None,
                                            optional = True),
                requirements.IntRequirement(name = 'pte_value',
                                            description = "A PTE value to parse",
                                            default = None,
                                            optional = True),
                requirements.BooleanRequirement(name = 'subsec_pte',
                                            description = ("Tries to gather the SUBSECTION PTE for "
                                                           "the given vaddr."),
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

        return renderers.TreeGrid([("PID", int),
                                   ("Process Name", str),
                                   ("Output", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          self.context,
                                          layer_name = layer_name,
                                          symbol_table = symbol_table,
                                          filter_func = filter_func)))


    def _generator(self, procs):
        if self.config.get('pte_paddr') is not None:
            self._initialize_internals()
            # In this case, we gather the associated process from the PTE's
            # physical address
            pte_run = self.resolve_pte_by_pte_paddr(self.config.get('pte_paddr'))
            if pte_run is None:
                vollog.warning("Unable to resolve PTE.")
                return
            if pte_run.proc:
                proc_name = utility.array_to_string(pte_run.proc.ImageFileName)
            else:
                proc_name = "N/A"
            yield (0, (
                pte_run.pid or -1,
                proc_name,
                "\n\n" + pte_run.get_full_string_repr()))

        elif self.config.get('pte_value') is not None:
            self._initialize_internals()
            pte_run = self.resolve_pte_by_pte_value(self.config.get('pte_value'))
            if pte_run is None:
                vollog.warning("Unable to resolve PTE.")
                return
            if pte_run.proc:
                proc_name = utility.array_to_string(pte_run.proc.ImageFileName)
            else:
                proc_name = "N/A"

            yield (0, (
                pte_run.pid or -1,
                proc_name,
                "\n\n" + pte_run.get_full_string_repr()))

        else:
            for proc in procs:
                self.init_for_proc(proc)
                pte_run = None
                if self.config.get('vaddr') is not None:
                    if self.config.get('subsec_pte'):
                        vaddr = self.config.get('vaddr')
                        vad_start, vad_end, vad = self.get_vad_for_vaddr(vaddr)
                        sub_wrp = SubsecProtoWrapper(vad, self._PAGE_BITS, self._PTE_SIZE)
                        pte_vaddr = sub_wrp.get_pteaddr_for_vaddr(vad, vad_start, vad_end, vaddr)
                        pte_run = self.resolve_pte_by_pte_vaddr(pte_vaddr, vaddr=vaddr, is_proto=True)

                    else:
                        pte_run = self.resolve_pte_by_vaddr(self.config.get('vaddr'))

                elif self.config.get('pte_vaddr') is not None:
                    pte_run = self.resolve_pte_by_pte_vaddr(self.config.get('pte_vaddr'))

                if pte_run:
                    yield (0, (
                        self.pid,
                        self.proc_name,
                        "\n\n" + pte_run.get_full_string_repr()))
