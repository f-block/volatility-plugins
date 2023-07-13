#  This plugin reveals modifications to mapped image files.
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

import logging, math, struct, re, json
from dataclasses import dataclass, field
from functools import cached_property
from typing import Dict, Tuple, Generator, List, Type, Optional
from volatility3.framework import interfaces, renderers, constants
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows.ptemalfind import PteMalfind
from volatility3.plugins.windows.pe_parser import PeWrapper
from volatility3.plugins.windows.ptenum import PteRun, PteEnumerator
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import resources
from volatility3.framework.interfaces.objects import ObjectInterface


vollog = logging.getLogger(__name__)

CAPSTONE_PRESENT = False
try:
    import capstone
    CAPSTONE_PRESENT = True
except ImportError:
    pass

try:
    COLORAMA_PRESENT = True
    from colorama import init as colorama_init
    from colorama import Fore
    from colorama import Style
except ImportError:
    COLORAMA_PRESENT = False
    vollog.debug("Coloring library colorama not found, so coloring differences "
                 "will be deactivated.")

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

# Currently not used
# class ModificationType(Enum):
#     """Enum representing the type of modification."""
#     hook = 1
#     return_patch = 2
#     clr_mod = 3
#     mapview = 4
#     unknown = 5


@dataclass
class HookTarget(object):
    target_vaddr: int = None
    target_page: PteRun = None
    _target_vad: ObjectInterface = None
    _target_vad_name: str = None
    _target_is_img: bool = None
    target_is_mod: bool = None
    target_bytes: bytes = None
    additional_bytes: bytes = None
    insts: List[capstone.CsInsn] = None
    ptenum: PteEnumerator = None

    @property
    def target_vad(self):
        if self._target_vad is None and self.target_page is not None:
            self._target_vad = self.target_page.get_vad()[2]
        return self._target_vad

    @property
    def target_vad_name(self):
        if not self.target_is_img:
            return "Anonymous VAD"
        if self._target_vad_name is None and self.target_vad is not None:
            self._target_vad_name = PteMalfind.get_vad_filename(self.target_vad)
        return self._target_vad_name

    @property
    def target_is_img(self):
        if self._target_is_img is None and self.target_vad is not None:
            self._target_is_img = \
                self.ptenum.vad_contains_image_file(self.target_vad)
        return self._target_is_img

    @property
    def target_is_unmodified_img(self):
        if not self.target_vad:
            return None
        return self.target_page.is_unmodified_img_page


@dataclass
class AnalysisState(object):
    """Class that holds the analysis objects and results for the currently
    analyzed modified bytes."""
    
    # Non optional attribute
    ptenum: PteEnumerator
    # Current instance of ImageMalfind
    img_malfind: object
    # A list of virtual addresses for each modified byte
    mod_byte_addrs: list[int] = None
    # The corresponding page for the current modification
    mod_page: PteRun = None
    # The offset from the beginning of the page's virtual address up until
    # the first modified byte.
    _mod_page_offset: int = None
    # The corresponding VAD for the current modification
    _mod_vad: ObjectInterface = None
    _mod_vad_name: str = None
    # The corresponding ImageSectionObject page for the VAD page.
    _img_page: PteRun = None
    # If we have a hook, this list will keep track of all followed redirects
    hook_targets: list[HookTarget] = field(default_factory=list) 
    _img_pe_file: PeWrapper = None
    # TODO make this also a class
    _hit_context: dict = None
    # Holds the section name(s) where the current modifications occured.
    # For example: ".text"
    sec_name: str = None
    # In case of a hook, this indicates if we think it is benign
    is_benign_mod: bool = None
    # Keeps a pointer to the ntdll for certain tests
    ntdll_img_file: PeWrapper = None
    precontext: int = 0
    postcontext: int = 0

    @property
    def img_pe_file(self):
        if self._img_pe_file is None:
            self._img_pe_file = self.img_malfind.get_pe_wrapper(self.mod_vad, self.ptenum)
        return self._img_pe_file

    @property
    def mod_page_offset(self):
        """The offset from the beginning of the page's virtual address up until
        the first modified byte."""
        if self._mod_page_offset is None and \
                None not in [self.mod_page, self.first_mod_vaddr]:
            self._mod_page_offset = self.first_mod_vaddr - self.mod_page.vaddr
        return self._mod_page_offset

    @property
    def mod_vad(self):
        if self._mod_vad is None and self.mod_page is not None:
            self._mod_vad = self.mod_page.get_vad()[2]
        return self._mod_vad

    @property
    def mod_vad_name(self):
        if self._mod_vad_name is None and self.mod_vad is not None:
            self._mod_vad_name = PteMalfind.get_vad_filename(self.mod_vad)
        return self._mod_vad_name

    @property
    def mod_byte_num(self):
        """The number of actually modified bytes. If the first modified byte is
        at 0x1000 and only one other byte got modified at 0x1008, this function
        would return: 2"""
        return len(self.mod_byte_addrs)

    @property
    def first_mod_vaddr(self):
        """The address of the first modified byte."""
        if self.mod_byte_addrs is not None:
            return self.mod_byte_addrs[0]
        return None

    @cached_property
    def first_analysis_vaddr(self):
        """The address of the first byte in scope for analysis
        (takes the precontext and function offset into account)."""
        first_vaddr = self.first_mod_vaddr - self.precontext
        if 'offset' in self.hit_context and 0 < self.hit_context['offset'] <= 2:
            first_vaddr -= self.hit_context['offset']
        return first_vaddr

    @property
    def mod_byte_range(self):
        """The modification range: The number of bytes from the first to the
        last modified byte. If the first modified byte is at 0x1000 and only one
        other byte got modified at 0x1008, this function returns: 9"""
        return self.mod_byte_addrs[-1] - self.mod_byte_addrs[0] + 1

    @property
    def analysis_byte_range(self):
        return self.mod_byte_range \
               + (self.first_mod_vaddr - self.first_analysis_vaddr) \
               + self.postcontext

    @cached_property
    def hit_context(self):
        return self.img_pe_file.get_export_with_ctx_for_vaddr(self.first_mod_vaddr)

    @property
    def img_page(self) -> PteRun:
        """The corresponding ImageSectionObject page for the VAD page."""
        if self._img_page is None:
            try:
                pte_addr, pte_value = self.ptenum._get_protopte_addr_and_val_via_vad(self.mod_page.vaddr)
                pte_paddr = self.ptenum.proc_layer.translate(pte_addr)[0]
                self._img_page = self.ptenum.resolve_pte(self.mod_page.vaddr, pte_value, pte_paddr, is_proto=True, pte_vaddr=pte_addr, zero_ret=False)
            except Exception:
                pass
        return self._img_page

    @cached_property
    def mod_bytes(self):
        """The bytes resulting from the modification (uses mod_byte_range),
        without any pre/postcontext or adjustments regarding function offsets.
        """
        offset = self.first_mod_vaddr - self.mod_page.vaddr
        return self.mod_page.read(rel_off=offset, length=self.mod_byte_range)

    @cached_property
    def analysis_bytes(self):
        """The bytes used for analysis. In contrast to mod_bytes, these can
        contain pre/postcontext bytes or adjustments for function offsets."""
        try:
            return self.ptenum.proc_layer.read(self.first_analysis_vaddr,
                                               self.analysis_byte_range)
        except Exception:
            offset = self.first_analysis_vaddr - self.mod_page.vaddr
            return self.mod_page.read(rel_off=offset,
                                      length=self.analysis_byte_range)

    @cached_property
    def mod_insts(self) -> List[capstone.CsInsn]:
        """Returns a list of assembly instructions gathered from mod_bytes."""
        return list(self.img_malfind.disassembler.disasm(
            self.mod_bytes, self.first_mod_vaddr))

    @cached_property
    def analysis_insts(self) -> List[capstone.CsInsn]:
        """Returns list of assembly instructions gathered from analysis_bytes.
        These are the instructions used primarily."""
        return list(self.img_malfind.disassembler.disasm(
            self.analysis_bytes, self.first_analysis_vaddr))

    def chunk_reset(self):
        if 'hit_context' in self.__dict__:
            del self.__dict__['hit_context']
        if 'first_analysis_vaddr' in self.__dict__:
            del self.__dict__['first_analysis_vaddr']
        self.mod_byte_addrs = None
        if 'mod_bytes' in self.__dict__:
            del self.__dict__['mod_bytes']
        if 'analysis_bytes' in self.__dict__:
            del self.__dict__['analysis_bytes']
        if 'mod_insts' in self.__dict__:
            del self.__dict__['mod_insts']
        if 'analysis_insts' in self.__dict__:
            del self.__dict__['analysis_insts']
        self.hook_targets = list()
        self.is_benign_mod = None

    def page_reset(self):
        self.chunk_reset()
        self.sec_name = None
        self.mod_page = None
        self._img_page = None

    def vad_reset(self):
        self.page_reset()
        self._img_pe_file = None
        self._mod_vad = None
        self._mod_vad_name = None


class ImageMalfind(interfaces.plugins.PluginInterface):

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
                requirements.IntRequirement(name = 'precontext',
                                            description = "Number of bytes before the actual first modified byte to include",
                                            default = None,
                                            optional = True),
                requirements.IntRequirement(name = 'postcontext',
                                            description = "Number of bytes after the actual last modified byte to include",
                                            default = None,
                                            optional = True),
                requirements.BooleanRequirement(name = 'disable_filtering',
                                            description = "",
                                            default = False,
                                            optional = True),
                requirements.URIRequirement(name="filters",
                                            description="Additional allow-list filters (as a json-file)",
                                            optional=True),
                requirements.BooleanRequirement(name = 'include_demand_zero',
                                            description = ("Include PTEs that have yet no corresponding page. This will also include \"PTEs\" that "
                                                           "not yet have any valid vaddr, but a valid Page Table, and might lead to Warnings/False "
                                                           "Positives if not dealt with accordingly."),
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
                                   ("Process", str),
                                   ("Section name(s)", str),
                                   ("First modified byte", format_hints.Hex),
                                   ("Function(s)", str),
                                   ("Modified Module", str),
                                   ("Modified bytes Count", int),
                                   ("Seperator1", str),
                                   ("Orig Hexdump", format_hints.HexBytes), 
                                   ("Orig Disassembly", interfaces.renderers.Disassembly),
                                   ("Seperator2", str),
                                   ("New Hexdump", format_hints.HexBytes), 
                                   ("New Disassembly", interfaces.renderers.Disassembly),
                                   ("Target Description", str),
                                   ("Target Module", str),
                                   ("Target Hexdump", format_hints.HexBytes), 
                                   ("Target Disassembly", interfaces.renderers.Disassembly)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          self.context,
                                          layer_name = layer_name,
                                          symbol_table = symbol_table,
                                          filter_func = filter_func)))


    def get_context_for_offsets(self, img_pe_file, diff_offsets):
        """Retrieves context information for the given offsets within the
        given PE file (e.g., the surrounding section name)."""
        sections = set()
        contexts = set()
        ctx_name = ""
        for diff_off in diff_offsets:
            section = img_pe_file.get_section_name_by_vaddr(diff_off)
            if section:
                sections.add(section)

            context = img_pe_file.get_context_by_vaddr(diff_off)
            if context:
                contexts.add(context)

        if not contexts and not sections:
            ctx_name = "None found"
        else:
            ctx_name = ", ".join(sections)
            if ctx_name and contexts:
                ctx_name += "; "
            ctx_name += ", ".join(contexts)
        return ctx_name


    def get_target_vaddr_for_instructions(self, insts, target_data=None):
        """Parses the given instructions and retrieves a potential
        redirect-target. This function does, however, not parse any redirect,
        but expects those observed in the context of benign hooks. In all other
        cases, it will not return a target vaddr, even if the instructions
        would redirect to a certain address."""
        if len(insts) == 0 or insts[0].mnemonic not in ['jmp', 'movabs']:
            return None
        (regs_read, regs_write) = insts[0].regs_access()

        if insts[0].mnemonic == 'jmp':
            # These jmps are expected at a second hop.
            if target_data and insts[0].op_str == 'qword ptr [rip - 0xe]':
                return struct.unpack(self.unpack_str,
                                     target_data[0:self.ptr_size])[0]
            elif target_data and insts[0].op_str == 'qword ptr [rip]':
                # The target_data array always contains ptr_size bytes before
                # the jump target.
                ptr_off = self.ptr_size + insts[0].size
                return struct.unpack(self.unpack_str,
                                     target_data[ptr_off:ptr_off + self.ptr_size])[0]

            # We currently do not accept other redirects involving registers
            else:
                if (len(regs_read) + len(regs_write)) > 0:
                    return None
                # Instructions such as jmp 0x1234
                return insts[0].operands[0].imm

        elif insts[0].mnemonic == 'movabs':
            if len(insts) < 2 or insts[1].mnemonic != 'jmp':
                return None
            first_op = insts[0].operands[0]
            if insts[1].operands[0].reg != first_op.reg:
                return None
            sec_op = insts[0].operands[1]
            if (len(regs_write)) <= 0 or \
                    sec_op.type != capstone.CS_OP_IMM:
                return None
            return sec_op.imm
        return None


    def is_allowlisted_target(self, analysis_state):

        analysis_state.is_benign_mod = False
        if not analysis_state.hook_targets:
            return
        last_target = analysis_state.hook_targets[-1]

        if not last_target.target_is_unmodified_img:
            # A modified image file page will not be allow-listed
            return
        modified_vad_name = analysis_state.mod_vad_name.lower()
        target_vad_name = last_target.target_vad_name.lower()
        proc_name = analysis_state.ptenum.proc_name.lower()
        for filter in self.allow_list_filters:
            # While we use search here (which matches anywhere in the string),
            # it is advised to match as much as possible.
            if re.search(filter['process'], proc_name) and \
                    re.search(filter['modified_vad'], modified_vad_name) and \
                    re.search(filter['target_vad'], target_vad_name):
                analysis_state.is_benign_mod = True
                return


    def _hook_size_verification(self, analysis_state):
        if analysis_state.mod_byte_range > self.MAX_CHUNK_SIZE:
            return False

        # Comparing the range of modified bytes against the bytes from the
        # resulting successful disassembled instructions.
        insts_byte_count = sum([len(x.bytes) for x in analysis_state.analysis_insts])
        diff = analysis_state.analysis_byte_range - insts_byte_count
        if diff > self.MAX_BYTE_DIFF:
            return False

        # We currently only consider hooks right at the beginning of functions.
        # This test tries to make it harder to fool the allowlisting
        # algorithm, by e.g., planting byte(s) right before the
        # API (the first modified byte in this case, still belongs to the
        # previous API), resulting in wrong disassembled instructions,
        # and doing a malicious jump at the beginning of the
        # function. This attack could work, since we only have special treatment
        # for hooks a few bytes after, but not before the start of a function.
        if analysis_state.hit_context and \
                'offset' in analysis_state.hit_context and \
                analysis_state.hit_context['offset'] >= 6:
            # There are a few cases (especially with AVs) where the offset
            # is large, mainly because functions get patched for which we
            # do not have symbols. So as a last step, we check the distance to
            # the potential next exported function and only return False if we
            # are close to this function.
            if 'distance_to_next_api' in analysis_state.hit_context and \
                    analysis_state.hit_context['distance_to_next_api'] <= analysis_state.mod_byte_range:
                return False
            else:
                n_redirs = 0
                for ins in analysis_state.analysis_insts:
                    for group_id in ins.groups:
                        if ins.group_name(group_id) in self.REDIR_OP_GROUPS:
                            # (multiple) int3 instructions are commonly encountered
                            # for benign patches
                            if ins.mnemonic == 'int3':
                                continue
                            n_redirs += 1
                if n_redirs > 1:
                    return False
        return True


    def test_mapview_sections(self, analysis_state):
        if not (analysis_state.mod_vad_name.lower().endswith('\\chrome_elf.dll') or \
                analysis_state.mod_vad_name.lower().endswith('\\msedge_elf.dll')):
            return False
        if not analysis_state.sec_name in self.CHROMIUM_SECTIONS:
            return False
        if not analysis_state.img_pe_file:
            return False

        if analysis_state.sec_name == '.oldntma':
            # In this case, we check if the modified bytes contain one pointer
            # to the .crthunk section.
            if analysis_state.mod_byte_range > self.ptr_size:
                return False
            pe_section = analysis_state.img_pe_file.get_section_by_vaddr(analysis_state.first_mod_vaddr)
            if not pe_section:
                return False
            sec_addr = pe_section.get_VirtualAddress_adj()
            vad_start = analysis_state.mod_vad.get_start()
            sec_vaddr = sec_addr + vad_start
            # Number of bytes from the first modified byte to the beginning
            # of the section (mainly takes account for null bytes).
            mod_offset = analysis_state.first_mod_vaddr - sec_vaddr
            if mod_offset >= self.ptr_size:
                return False
            # We fill the modified bytes up to a full pointer size.
            ptr_bytes = (b'\x00' * mod_offset) + analysis_state.mod_bytes
            ptr_bytes += b'\x00' * \
                (self.ptr_size - analysis_state.mod_byte_range - mod_offset)
            ntmap_ptr = struct.unpack(self.unpack_str, ptr_bytes)[0]

            # After parsing the modified bytes as a pointer, we check its target
            # for being the .crthunk section
            target_section = analysis_state.img_pe_file.get_section_by_vaddr(ntmap_ptr)
            if not target_section:
                return False
            t_sec_name = analysis_state.img_pe_file.get_section_name_by_vaddr(ntmap_ptr)
            if t_sec_name != '.crthunk':
                return False
            t_sec_addr = target_section.get_VirtualAddress_adj()
            t_sec_vaddr = t_sec_addr + vad_start
            return t_sec_vaddr == ntmap_ptr

        ntdll_dlls = None
        if not analysis_state.ntdll_img_file:
            ntdll_dlls = \
                [(vad_start, vad) for vad_start, _, vad in analysis_state.ptenum._proc_vads \
                  if PteMalfind.get_vad_filename(vad).lower().endswith('\\ntdll.dll')]
            if len(ntdll_dlls) > 1:
                vollog.warning("Seems like ntdll.dll is loaded twice. Might "
                               "be something malicious.")
            elif len(ntdll_dlls) == 0:
                return False

        vad_start, vad = ntdll_dlls[0]
        ntdll_img_file = self.get_pe_wrapper(vad, analysis_state.ptenum)
        analysis_state.ntdll_img_file = ntdll_img_file

        ntmap_export = ntdll_img_file.get_export_for_name("ZwMapViewOfSection")
        if not ntmap_export:
            ntmap_export = ntdll_img_file.get_export_for_name("NtMapViewOfSection")
        if not ntmap_export:
            return False
        ntmap_offset, _ = ntmap_export
        rva = ntmap_offset - vad_start

        return ntdll_img_file.get_pe_data(rva, analysis_state.mod_byte_range) == analysis_state.mod_bytes


    def test_avg_return_patch(self, analysis_state):
        vollog.debug(
            "Testing for AVG SetUnhandledExceptionFilter patch "
            f"at 0x{analysis_state.first_mod_vaddr:x} in VAD "
            f"{analysis_state.mod_vad_name:s} for Process "
            f"{analysis_state.ptenum.proc_name:s} with PID: "
            f"{analysis_state.ptenum.pid:d}")
        if 'offset' in analysis_state.hit_context and \
                analysis_state.hit_context['offset'] > 1:
            return False
        if analysis_state.mod_byte_range > 8:
            return False
        if not analysis_state.mod_vad_name.lower().endswith('\\kernel32.dll'):
            return False
        if not analysis_state.ptenum.proc_name.lower() in self.AVG_RETURN_PATCH_PROCS:
            return False

        insts_byte_count = sum([len(x.bytes) for x in analysis_state.mod_insts])
        if insts_byte_count > analysis_state.mod_byte_range:
            return False
        if len(analysis_state.mod_insts) < 2:
            return False

        if analysis_state.mod_insts[1].mnemonic != 'ret' or \
                analysis_state.mod_insts[1].op_str != '':
            return False

        return analysis_state.mod_insts[0].mnemonic == 'xor' and \
            analysis_state.mod_insts[0].op_str in ['eax, eax', 'rax, rax']


    @staticmethod
    def _get_tlsslots_info(ptenum):
        try:
            teb = ptenum.kernel.get_type("_TEB")
            tls_slots_offset = teb.vol.members['TlsSlots'][0]
            tls_slots_size = teb.vol.members['TlsSlots'][1].size
            return (tls_slots_offset, tls_slots_size)
        except Exception:
            return (None, None)

        return (None, None)


    def test_clr_patches(self, analysis_state):
        if not analysis_state.mod_vad_name.lower().endswith('\\clr.dll'):
            return False
        if analysis_state.mod_byte_range > 16:
            return False

        tls_slots_offset, tls_slots_size = self._get_tlsslots_info(analysis_state.ptenum)
        tls_slots_end = tls_slots_offset + tls_slots_size
        if tls_slots_offset is None:
            return False
        tls_msb_min = tls_slots_offset >> 8
        tls_msb_max = tls_slots_end >> 8

        insts = analysis_state.mod_insts
        if analysis_state.mod_byte_range <= 2:
            # We test for a simple change within the TlsSlots array.
            # We need more bytes to get the whole instruction in this case
            # We expect at least one of the two bytes for the TlsSlots-index
            # to be changed. In case we only have one byte modified, we need to
            # figure out which one of the two, in order to get other bytes
            # correctly.
            # First, we read enough bytes to test against. This is 2 bytes after
            # the array-index and 5 before.
            tmp_bytes = analysis_state.mod_page.read(
                rel_off=analysis_state.mod_page_offset - 6, length=11)
            if analysis_state.mod_byte_range == 2 or \
                    tls_msb_min <= tmp_bytes[-4] <= tls_msb_max and \
                    tmp_bytes[-2] == tmp_bytes[-3] == 0:
                # Either both or only the least significant byte has been modified. 
                tmp_bytes = tmp_bytes[1:-1]

            elif tls_msb_min <= tmp_bytes[-5] <= tls_msb_max and \
                    tmp_bytes[-3] == tmp_bytes[-4] == 0:
                # Only the most significant byte has been modified. 
                tmp_bytes = tmp_bytes[:-2]

            else:
                # Unknown modification
                return False

            new_insts = None
            try:
                new_insts = list(self.disassembler.disasm(tmp_bytes, 0))
            except Exception:
                return False

            if new_insts is None or len(new_insts) == 0 or len(new_insts) > 1:
                return False

            insts = new_insts
        elif insts is None or len(insts) != 2:
            return False
        # In both cases, the index patch (max 2 bytes) and the patch of a jump
        # instruction (around 10 modified bytes), we expect an instruction 
        # such as 'mov r11, qword ptr gs:[0x1590]'.
        # The main difference being, in the second case we also expect a 
        # follow up return.
        if analysis_state.mod_byte_range > 2 and insts[1].mnemonic != 'ret':
            return False
        operands = insts[0].operands
        # We expect an instruction such as 'mov r11, qword ptr gs:[0x1590]'
        # with an index within the TlsSlots array.
        return insts[0].mnemonic == 'mov' and operands is not None \
            and len(operands) == 2 \
            and (insts[0].reg_name(operands[1].reg) in ['fs', 'gs']) \
            and (tls_slots_offset <= operands[1].mem.disp < tls_slots_end)


    def process_potential_hook(self, analysis_state, additional_bytes=False, stop_mod_ver=False):
        """Processes potential hook related redirects and returns a class
        with the redirect-target and an indication, whether or not the hook
        appears to be benign.
        
        additional_bytes: This param is used for a special hook case, where
        additional bytes before/after the hook target are included.
        
        stop_mod_ver: Prevents endless loops while following redirects to
        modified pages.
        """

        analysis_state.is_benign_mod = False

        # Currently, we follow redirects only two times.
        if len(analysis_state.hook_targets) >= self.MAX_DEPTH:
            return

        target_data = None
        if len(analysis_state.hook_targets) == 0:
            curr_insts = analysis_state.analysis_insts
            curr_page = analysis_state.mod_page
        else:
            curr_insts = analysis_state.hook_targets[-1].target_insts
            curr_page = analysis_state.hook_targets[-1].target_page
            if additional_bytes:
                target_data = analysis_state.hook_targets[-1].additional_bytes

        target = self.get_target_vaddr_for_instructions(curr_insts, target_data=target_data)
        if target is None:
            return

        hook_target = HookTarget(ptenum=analysis_state.ptenum,
                                 target_vaddr=target)
        analysis_state.hook_targets.append(hook_target)
        hook_target.target_page = analysis_state.ptenum.resolve_pte_by_vaddr(target, zero_ret=False)

        if not hook_target.target_page:
            return
        rel_off = target - hook_target.target_page.vaddr
        hook_target.target_bytes = hook_target.target_page.read(rel_off=rel_off,
                                                                length=0x10)
        try:
            hook_target.target_insts = list(self.disassembler.disasm(
                hook_target.target_bytes, target))
        except Exception:
            hook_target.target_insts = list()

        # We verify sizes only once for the initial hook
        if len(analysis_state.hook_targets) == 1 and \
                not self._hook_size_verification(analysis_state):
            return

        if hook_target.target_page.get_vad()[0] == curr_page.get_vad()[0]:
            # A jump to the same module is not considered benign
            return

        if hook_target.target_is_img:
            if hook_target.target_page.is_unmodified_img_page:
                self.is_allowlisted_target(analysis_state)
            elif not stop_mod_ver:
                # The target is a modified image page, so we test the page
                # for being a benign modification, and in this case, consider
                # this hook as benign.
                analysis_state_new = AnalysisState(analysis_state.ptenum, self)
                analysis_state_new.mod_page = hook_target.target_page
                cont_diff_chunks = self.get_diff_chunks(analysis_state_new)
                if cont_diff_chunks is None:
                    return
                for diff_chunk in cont_diff_chunks:
                    analysis_state_new.chunk_reset()
                    analysis_state_new.mod_byte_addrs = diff_chunk
                    self.process_potential_hook(analysis_state_new, stop_mod_ver=True)
                    # TODO as we currently check the target page in this case
                    # at least twice, we should add a checklist of already
                    # processed pages.
                    if not analysis_state_new.is_benign_mod:
                        return
                analysis_state.is_benign_mod = True

        else:
            # We now check for hooks that consist of two redirects, e.g., used 
            # by Office and AVG.
            # Those are jumps that either read a pointer before or after the
            # jmp instruction, so we read pointer-size bytes before/after.
            rel_off = target - self.ptr_size - hook_target.target_page.vaddr
            hook_target.additional_bytes = \
                hook_target.target_page.read(rel_off=rel_off, length=0x18)
            self.process_potential_hook(analysis_state, additional_bytes=True)


    def get_diff_chunks(self, analysis_state):
        page = analysis_state.mod_page
        ptenum = analysis_state.ptenum
        img_pe_file = analysis_state.img_pe_file
        img_page = analysis_state.img_page
        cont_diff_chunks = list()

        vad_page_data = page.read()
        if vad_page_data is None:
            return None
        # Check if orig data is available
        if img_page and img_page.is_data_available:
            img_page_data = img_page.read()
            if img_page_data is None:
                return None
            diff_offsets = list()
            if not (img_page.length == len(vad_page_data) == len(img_page_data)):
                return None
            for i in range(img_page.length):
                if vad_page_data[i] != img_page_data[i]:
                    diff_offsets.append(page.vaddr + i)
            if len(diff_offsets) == 0:
                vollog.info(
                "Page at 0x{:x} in process {:d} and VAD {:s} "
                "has been flagged modified but all bytes still "
                "(or again) match the ImageSectionObject. Since we "
                "have not identified any difference, we are "
                "skipping this page."
                .format(page.vaddr, ptenum.pid, analysis_state.mod_vad_name))
                return None

            if len(diff_offsets) > 1:
                i = 0
                while i < len(diff_offsets):
                    curr_chunk = [diff_offsets[i]]
                    i += 1
                    while i < len(diff_offsets) and diff_offsets[i] < curr_chunk[-1] + self.MAX_CHUNK_DISTANCE:
                        curr_chunk.append(diff_offsets[i])
                        i += 1
                    cont_diff_chunks.append(curr_chunk)
            else:
                cont_diff_chunks.append([[diff_offsets[0]]])

            if img_pe_file:
                analysis_state.sec_name = self.get_context_for_offsets(img_pe_file, diff_offsets)
            else:
                analysis_state.sec_name = "N/A"

        else:
            base_str = (
                "Unable to get the base data for PID {:d} {:s} and "
                "virtual address 0x{:x} in the VAD {:s}, so a "
                "direct comparison is not possible. Hence, we "
                "simply show the first 64 bytes of the page, but "
                "note that these might not have been modified. "
                "Reason for unavailable data: "
                .format(ptenum.pid, ptenum.proc_name, page.vaddr, analysis_state.mod_vad_name))
            if img_page and img_page.is_swapped:
                vollog.warning(
                    base_str +
                    "Potentially because the corresponding "
                    "pagefile is not provided: "
                    "Pagefile idx: {:d}."
                    .format(page.pagefile_idx))
            else:
                vollog.warning(
                    base_str +
                    "Data not available from RAM or "
                    "pagefile. Would need to be loaded from "
                    "disk.")

            if img_pe_file:
                doffsets = list(range(page.vaddr, page.vaddr + page.length, 8))
                analysis_state.sec_name = self.get_context_for_offsets(img_pe_file, doffsets)
            else:
                analysis_state.sec_name = "N/A"

            cont_diff_chunks = [[page.vaddr, page.vaddr + page.length - 1]]

        return cont_diff_chunks


    def process_filters(self, analysis_state):
        # Even if filtering is disabled, we check for hooks and parse
        # potential targets
        self.process_potential_hook(analysis_state)
        if not self.config['disable_filtering']:
            ptenum = analysis_state.ptenum
            if analysis_state.is_benign_mod:
                last_target = analysis_state.hook_targets[-1]
                vollog.info(
                    "Filtered potential legitimate hook at "
                    f"0x{analysis_state.first_mod_vaddr:x} in VAD "
                    f"{analysis_state.mod_vad_name:s} for PID: {ptenum.pid:d} "
                    f"{ptenum.proc_name:s} with a jump to "
                    f"0x{last_target.target_vaddr:x} in the "
                    f"image file {last_target.target_vad_name:s}")

            # Now we test for special cases.
            # First, the chromium NtMapViewOfSection hook
            elif self.test_mapview_sections(analysis_state):
                analysis_state.is_benign_mod = True
                vollog.info(
                    "Filtered chromium NtMapViewOfSection "
                    f"hook in VAD {analysis_state.mod_vad_name:s}, "
                    f"Section {analysis_state.sec_name:s} "
                    f"for Process {ptenum.proc_name:s} "
                    f"PID: {ptenum.pid:d} ")
            # Second, the AVG SetUnhandledExceptionFilter patch
            elif self.test_avg_return_patch(analysis_state):
                analysis_state.is_benign_mod = True
                vollog.info(
                    "Filtered AVG SetUnhandledExceptionFilter "
                    f"patch in VAD {analysis_state.mod_vad_name:s}, "
                    f"Section {analysis_state.sec_name:s} "
                    f"for Process {ptenum.proc_name:s} "
                    f"PID: {ptenum.pid:d} ")
            # Lastly, the CLR related patches
            elif self.test_clr_patches(analysis_state):
                analysis_state.is_benign_mod = True
                vollog.info(
                    "Filtered clr.dll patches "
                    f"in VAD {analysis_state.mod_vad_name:s}, "
                    f"Section {analysis_state.sec_name:s} "
                    f"for Process {ptenum.proc_name:s} "
                    f"PID: {ptenum.pid:d} ")


    def initialize_internals(self):
        # Maximum number of hops to take while following hook redirects
        self.MAX_DEPTH = 2

        # Maximum number of bytes (length) that differ between the modified
        # bytes and the resulting bytes from the disassembled instructions.
        # On disassembly errors, no further instructions are generated, which
        # could indicate a hiding-attempt or non-machine code bytes.
        self.MAX_BYTE_DIFF = 1

        # Threshold for unmodified bytes that separate modified chunks.
        # Modified bytes that have at least X unmodified bytes between them,
        # are treated as two separate chunks of modified bytes.
        self.MAX_CHUNK_DISTANCE = 8

        # Currently, only chunks of maximum 16 modified bytes are considered as
        # candidates for API hooks and hence for allowlist-testing.
        # Modifications with a bigger size are considered non-API hook related
        # (at least in the context of allowlisting).
        self.MAX_CHUNK_SIZE = 16

        # Capstone operation-groups, which are considered redirects
        self.REDIR_OP_GROUPS = ['jump', 'call', 'ret', 'iret', 'int']

        # PE sections in chrome_elf.dll, related to a benign chromium hook
        self.CHROMIUM_SECTIONS = ['.crthunk', '.oldntma']

        # We currently only support intel 32/64 bit
        self._disasm_types = {
            "intel": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "intel64": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            #"arm": capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            #"arm64": capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        for disas in self._disasm_types.values():
            disas.detail = True

        self.AVG_RETURN_PATCH_PROCS = \
            ['wsc_proxy.exe', 'avgsvc.exe', 'avgtoolssvc.ex',
             'aswidsagent.ex', 'avgui.exe']

        # Builtin allow-list
        self.allow_list_filters = [
            {'process': '^firefox\.exe$',
             'modified_vad': r'^\\windows\\system32\\(ntdll|kernelbase|user32|kernel32)\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\mozilla firefox\\(xul|mozglue)\.dll$'},
            {'process': '^firefox\.exe$',
             'modified_vad': r'^\\windows\\system32\\ntdll\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\mozilla firefox\\firefox\.exe$'},
            {'process': '^msedge\.exe$',
             'modified_vad': r'^\\windows\\system32\\ntdll\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\microsoft\\edge\\application\\[\d\.]+\\msedge_elf\.dll$'},
            {'process': '^msedge\.exe$',
             'modified_vad': r'^\\windows\\system32\\ntdll\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\microsoft\\edge\\application\\msedge\.exe$'},
            {'process': '^chrome\.exe$',
             'modified_vad': r'^\\windows\\system32\\ntdll\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\google\\chrome\\application\\[\d\.]+\\chrome_elf\.dll$'},
            {'process': '^chrome\.exe$',
             'modified_vad': r'^\\windows\\system32\\ntdll\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\google\\chrome\\application\\chrome\.exe$'},
            {'process': '^(winword|excel|outlook|onenotem)\.exe$',
             'modified_vad': r'^\\windows\\system32\\(advapi32|combase|ole32|oleaut32|ntdll|kernelbase|shell32|user32|kernel32|win32u)\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\microsoft office\\root\\vfs\\programfilescommonx64\\microsoft shared\\office\d+\\(mso|mso40uiwin32client|mso30win32client)\.dll$'},
            {'process': '^(winword|excel|outlook|onenotem)\.exe$',
             'modified_vad': r'^\\windows\\system32\\(advapi32|combase|ole32|oleaut32|ntdll|kernelbase|shell32|user32|kernel32)\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\common files\\microsoft shared\\clicktorun\\appvisvsubsystems(32|64)\.dll$'},
            {'process': '.',
             'modified_vad': r'^\\windows\\system32\\(advapi32|combase|oleaut32|ntdll|kernel32|taskschd)\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\avg\\antivirus\\(chrome_elf|aswjsflt|snxhk|aswhook)\.dll$'},
            {'process': '^firefox\.exe$',
             'modified_vad': r'^\\program files( \(x86\))?\\mozilla firefox\\(nss3|xul)\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\avg\\antivirus\\(aswjsflt|snxhk|aswhook)\.dll$'},
            {'process': '^firefox\.exe$',
             'modified_vad': r'^\\program files( \(x86\))?\\avg\\antivirus\\snxhk\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\mozilla firefox\\mozglue\.dll$'},
            {'process': '^chrome\.exe$',
             'modified_vad': r'^\\program files( \(x86\))?\\google\\chrome\\application\\[\d\.]+\\chrome\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\avg\\antivirus\\(aswjsflt|snxhk|aswhook)\.dll$'},
            {'process': '^msedge\.exe$',
             'modified_vad': r'^\\program files( \(x86\))?\\microsoft\\edge\\application\\[\d\.]+\\msedge\.dll$',
             'target_vad': r'^\\program files( \(x86\))?\\avg\\antivirus\\(aswjsflt|snxhk|aswhook)\.dll$'}
        ]

        self.img_pe_files = dict()
        self.config['only_image_files'] = True


    def load_additional_filters(self):
        if self.config.get("filters", None) is None:
            return
        with resources.ResourceAccessor().open(self.config["filters"], "rb") as filter:
            additional_filters_raw = filter.file.read().lower()
            additional_filters = json.loads(additional_filters_raw)
            self.allow_list_filters += additional_filters


    def get_pe_wrapper(self, vad, ptenum):
        vad_start = vad.get_start()
        obj_idx = vad_start
        if not vad.has_member("Subsection"):
            vollog.warning(
                "Given VAD at 0x{:x}has no Subsection pointer."
                "This shouldn't happen at this point."
                .format(vad_start))
        else:
            try:
                obj_idx = vad.Subsection.ControlArea.real
            except exceptions.InvalidAddressException:
                pass
        if obj_idx not in self.img_pe_files:
            if len(self.dll_addr_dict) == 0:
                dll_entries = list(ptenum.proc.load_order_modules())
                for dll_entry in dll_entries:
                    self.dll_addr_dict[dll_entry.DllBase] = dll_entry
            dll_entry = self.dll_addr_dict.get(vad_start, None)
            self.img_pe_files[obj_idx] = PeWrapper(self.context, self.config, self.config_path, vad, dll_entry, ptenum.proc_layer.name, ptenum.is_wow64, extensions=['img'])
        return self.img_pe_files[obj_idx]


    def _generator(self, procs):
        if not CAPSTONE_PRESENT: 
            vollog.error("The capstone framework is required but not available.")
            return None

        self.initialize_internals()
        self.load_additional_filters()

        for ptenum, result in PteMalfind.get_ptemalfind_data(
                procs, self.context, self.config, self._progress_callback):

            if ptenum.arch_proc not in self._disasm_types:
                vollog.error("Unsupported architecture: %s"
                             .format(ptenum.arch_proc))
                return None
            self.disassembler = self._disasm_types[ptenum.arch_proc]            
            self.ptr_size = 4 if ptenum.is_wow64 else 8
            self.unpack_str = '<I' if ptenum.is_wow64 else '<Q'
            self.dll_addr_dict = dict()
            analysis_state = AnalysisState(ptenum, self)
            # Not currently used
            wow64_ntdll_img_file = None
            for vad, xpages in result.items():
                analysis_state.vad_reset()
                analysis_state._mod_vad = vad
                img_pe_file = self.get_pe_wrapper(vad, ptenum)
                analysis_state._img_pe_file = img_pe_file
                if analysis_state.ntdll_img_file is None and \
                        analysis_state.mod_vad_name.lower().endswith('\\system32\\ntdll.dll'):
                    analysis_state.ntdll_img_file = img_pe_file
                elif analysis_state.mod_vad_name.lower().endswith('\\syswow64\\ntdll.dll'):
                    if not ptenum.is_wow64:
                        vollog.warning(
                            "SysWOW64 ntdll loaded in non WOW64 process. "
                            "Shouldn't be the case.")
                    wow64_ntdll_img_file = img_pe_file

                for page in xpages:
                    if not page.is_data_available:
                        vollog.info(
                            "Unable to get VAD data for PID {:d} {:s} and virtual "
                            "address 0x{:x} in VAD {:s}, potentially because "
                            "the corresponding pagefile is not provided, so "
                            "we can't analyze the current page and skip it"
                            .format(ptenum.pid, ptenum.proc_name, page.vaddr, analysis_state.mod_vad_name) +
                            (f": Pagefile idx: {page.pagefile_idx:d}." if page.pagefile_idx else "."))
                        continue
                    analysis_state.page_reset()
                    analysis_state.mod_page = page
                    hit_desc = None

                    cont_diff_chunks = self.get_diff_chunks(analysis_state)
                    if cont_diff_chunks is None:
                        continue
                    for diff_chunk in cont_diff_chunks:
                        analysis_state.chunk_reset()
                        analysis_state.mod_byte_addrs = diff_chunk
                        hit_desc = analysis_state.hit_context['repr']

                        self.process_filters(analysis_state)
                        if analysis_state.is_benign_mod and \
                                not self.config['disable_filtering']:
                            continue
                        # preparing hook target info for output
                        target_desc = '\n'
                        target_dis = None
                        target_data = b''
                        target_page = None
                        target_vad_name = ''
                        if analysis_state.hook_targets:
                            last_target = analysis_state.hook_targets[-1]
                            target_desc = "\n\nTarget:\n\tThe final target page "
                            t_vad_start = 0
                            if last_target.target_page:
                                target_page = last_target.target_page
                                t_vad_start, _, target_vad = target_page.get_vad()
                                if last_target.target_is_img:
                                    target_vad_name = last_target.target_vad_name
                                    target_desc += "is a"
                                    if target_page.orig_pte_is_sub_ptr:
                                        target_desc += "n unmodified page. "
                                    else:
                                        target_desc += " modified page. "
                                elif ptenum.vad_contains_file(target_vad):
                                    target_vad_name = last_target.target_vad_name
                                    target_desc += "belongs to a non image file object. "
                                else:
                                    target_vad_name = "private/shared"
                                    target_desc += "is anonymous memory (either private or shared). "

                                target_desc += f"Target VAD at 0x{t_vad_start:x}: "
                                target_data = last_target.target_bytes
                                if target_data is None:
                                    target_data = b''
                                target_dis = interfaces.renderers.Disassembly(
                                    target_data, last_target.target_vaddr, ptenum.arch_proc)
                            else:
                                target_desc += "could not be resolved."

                        if target_dis is None:
                            target_dis = interfaces.renderers.Disassembly(b'', 0, ptenum.arch_proc)

                        if target_data is None:
                            target_data = b''

                        data_new = analysis_state.analysis_bytes
                        page_offset = analysis_state.first_analysis_vaddr - analysis_state.mod_page.vaddr
                        img_offset = analysis_state.first_analysis_vaddr - vad.get_start()
                        size_to_dump = analysis_state.analysis_byte_range
                        diff_count = 0
                        # For printing with Volatility renderers, we need
                        # a multiple of 8 bytes.
                        if analysis_state.img_page and \
                                analysis_state.img_page.is_data_available:
                            size_to_dump = math.ceil(analysis_state.analysis_byte_range / 8) * 8
                            diff_count = analysis_state.mod_byte_num
                        else:
                            size_to_dump = 64
                            diff_count = -1

                        try:
                            data_new = ptenum.proc_layer.read(analysis_state.first_analysis_vaddr,
                                                              size_to_dump)
                        except Exception:
                            data_new = analysis_state.mod_page.read(
                                rel_off=page_offset, length=size_to_dump)

                        data_orig = img_pe_file.get_pe_data(img_offset,
                                                            size_to_dump)
                        if not data_orig and analysis_state.img_page and \
                                analysis_state.img_page.is_data_available:
                            data_orig = analysis_state.img_page.read(rel_off=page_offset,
                                                                     length=size_to_dump)
                        if not data_orig:
                            data_orig = b''

                        disas_orig = interfaces.renderers.Disassembly(
                            data_orig, analysis_state.first_analysis_vaddr, ptenum.arch_proc)

                        disas_new = interfaces.renderers.Disassembly(
                            data_new,
                            analysis_state.first_analysis_vaddr,
                            ptenum.arch_proc)
                        yield (0, (ptenum.pid,
                                    ptenum.proc_name,
                                    analysis_state.sec_name,
                                    format_hints.Hex(analysis_state.first_mod_vaddr),
                                    hit_desc,
                                    analysis_state.mod_vad_name,
                                    diff_count,
                                    "\n\nOrig Data\n",
                                    format_hints.HexBytes(data_orig),
                                    disas_orig,
                                    "\n\nNew Data\n",
                                    format_hints.HexBytes(data_new),
                                    disas_new,
                                    target_desc,
                                    target_vad_name,
                                    format_hints.HexBytes(target_data),
                                    target_dis))
