#  This module allows to enumerate and analyze all PTEs for a given process.
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

# Some parts are taken from Rekall https://github.com/google/rekall
# Code is marked accordingly.
#
# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty
# Michael Cohen
# Jordi Sanchez
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""This module allows to enumerate and analyze all PTEs for a given process and
can e.g. be used to get all executable pages for a given process. For a concrete
implementation see PteMalfind.

References:
https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/
https://github.com/f-block/DFRWS-USA-2019
https://dfrws.org/presentation/windows-memory-forensics-detecting-unintentionally-hidden-injected-code-by-examining-page-table-entries/
"""


from __future__ import annotations

import struct, logging, textwrap
from builtins import object
from past.utils import old_div
from typing import Dict, Tuple, Generator, List, Type, Optional
from functools import wraps, cached_property, lru_cache, cache

from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility, StructType
from volatility3.plugins.windows import pslist, vadinfo, info
from volatility3.framework import interfaces, constants, exceptions, symbols, objects
from volatility3.framework.interfaces.objects import ObjectInterface

vollog = logging.getLogger(__name__)

state_enum =  { 'HARD': 1,
                'TRANS': 2,
                'SOFT': 3,
                'SOFTZERO': 4,
                'PROTOPOINT': 5,
                'SUBSEC': 6,
                'PROTOVAD': 7
              }

state_enum_rev = {  1: 'HARD',
                    2: 'TRANS',
                    3: 'SOFT',
                    4: 'SOFTZERO',
                    5: 'PROTOPOINT',
                    6: 'SUBSEC',
                    7: 'PROTOVAD'
                 }

state_to_mmpte = { 1: '_MMPTE_HARDWARE',
                   2: '_MMPTE_TRANSITION',
                   3: '_MMPTE_SOFTWARE',
                   4: '_MMPTE_SOFTWARE',
                   5: '_MMPTE_PROTOTYPE',
                   6: '_MMPTE_SUBSECTION',
                   7: '_MMPTE_PROTOTYPE'
                 }

# These are not officially documented. Taken from 
# https://reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel
mm_prot_enum = { 0: 'MM_ZERO_ACCESS',
                 1: 'MM_READONLY',
                 2: 'MM_EXECUTE',
                 3: 'MM_EXECUTE_READ',
                 4: 'MM_READWRITE',
                 5: 'MM_WRITECOPY',
                 6: 'MM_EXECUTE_READWRITE',
                 7: 'MM_EXECUTE_WRITECOPY'
                }


def verify_initialized(func):
    """Function decorator: Verifies whether or not the PteEnumerator instance is
    already initialized."""
    @wraps(func)
    def wrapper_verify(self, *args, **kwargs):
        if not self._already_initialized:
            vollog.error("Error occured while calling function {:s}:"
                         "PteEnumerator not yet initialized. Aborting ..."
                         .format(func.__name__))
            return
        return func(self, *args, **kwargs)
    return wrapper_verify


def args_not_none(func):
    """Function decorator: Tests all positional arguments for being None, and
    returns None if they are."""
    @wraps(func)
    def wrapper_args_not_none(*args, **kwargs):
        for arg in args:
            if arg is None:
                return None
        return func(*args, **kwargs)
    return wrapper_args_not_none


def args_not_valid(func):
    """Function decorator: Simply tests for "not arg" and returns None if so."""
    @wraps(func)
    def wrapper_args_not_valid(*args, **kwargs):
        for arg in args:
            if not arg:
                return None
        return func(*args, **kwargs)
    return wrapper_args_not_valid


class MMPTE(StructType):
    """Class for pretty-printing MMPTE structs."""
    @staticmethod
    def _ssn(name):
        """Strips symbol name"""
        return name.split(constants.BANG)[1]

    def __repr__(self):
        result = "[" + self._ssn(self.vol.type_name) + "] @ " + hex(self.vol.offset) + "\n"
        for member, data in sorted(self.vol.members.items(), key=lambda x: x[1][0]):
            type_name = self._ssn(data[1].vol.type_name)
            if 'pointer' in type_name:
                try:
                    dest = self.member(member).dereference()
                    type_name += " to " + hex(dest.vol.offset) + " (" + self._ssn(dest.vol.type_name) + ")"
                except Exception:
                   pass
            elif 'bitfield' in type_name:
                bit_string = " (bits {:d}-{:d})".format(data[1].vol.start_bit,data[1].vol.end_bit)
                bit_length = data[1].vol.end_bit - data[1].vol.start_bit
                if bit_length == 1:
                    bit_string = " (bit {:d})".format(data[1].vol.start_bit)
                type_name = hex(self.member(member)) + " " + type_name + bit_string
            elif 'long' in type_name:
                type_name = hex(self.member(member)) + " " + type_name
            result += "  " + hex(data[0]) + " " + member + "   " + type_name + "\n"
        return result


class PteRun(object):
    """This class is used to represent a certain PTE and offers
    functions/properties to analyze it."""

    # These are fallback defaults, but should be set by PteEnumerator
    # during initialization
    _PAGE_BITS = 16
    # For an explanation, see comment in PteEnumerator._init_variables
    _SOFT_SWIZZLE_MASK = None
    _INVALID_SWAP_OFFSET = None
    _INVALID_SWAP_MASK = None
    _TRANS_SWIZZLE_MASK = None
    _INVALID_TRANS_OFFSET = None
    _INVALID_TRANS_MASK = None

    # PteRun must be initialized either with an instance of PteEnumerator or
    # with a Volatility context
    def __init__(self, init_obj: "Either instance of PteEnumerator or context",
                 proc, vaddr, length=None, phys_offset=None,
                 pte_value=None, pte_paddr=None, is_proto=None, state=None,
                 proto_ptr_run=None, is_exec=None, has_proto_set=None,
                 orig_pte_value=None, orig_pte_is_sub_ptr=None,
                 is_proto_ptr=None, pid=None, pte_vaddr=None,
                 data_layer=None, pte_layer=None, swap_offset=None,
                 pagefile_idx=None):

        self._proc = proc
        self._vaddr = vaddr
        self._length = length
        # Currently, it either points to the memory_layer or a swap_layer
        self._phys_offset = phys_offset
        self._swap_offset = swap_offset
        self._pagefile_idx = pagefile_idx
        self._pte_value = pte_value
        # Physical address of PTE
        self._pte_paddr = pte_paddr
        # Virtual address of PTE; Note: Currently only set for prototype PTEs
        self._pte_vaddr = pte_vaddr
        # is_proto is set for PrototypePTEs: PTEs not part of the MMU PTEs but
        # part of _SUBSECTION objects
        self._is_proto = is_proto
        # has_proto_set is set for MMU PTEs that have the Prototype flag set
        # in their MMPFN entry
        self._has_proto_set = has_proto_set
        self._orig_pte_value = orig_pte_value
        self._orig_pte_is_sub_ptr = orig_pte_is_sub_ptr
        # is_proto_ptr is set for MMU PTEs that either directly (PROTOPOINT)
        # or indirectly (PROTOVAD) point to a Prototype PTE
        self._is_proto_ptr = is_proto_ptr
        self._state = state
        self._proto_ptr_run = proto_ptr_run
        self._is_exec = is_exec
        # Layer to read page content from; typically either phys or swap_layer
        self._data_layer = data_layer
        # Layer to read PTE from; PTEs can also be paged
        self._pte_layer = pte_layer
        self._ptenum_handle = None
        self._context = None
        if init_obj is None:
            vollog.warning("Initializing PteRun without an init_obj is not"
                           "supported and will break some functionality.")
        elif isinstance(init_obj, PteEnumerator):
            self._ptenum_handle = init_obj
        else:
            self._context = init_obj


    @property
    def proc(self) -> ObjectInterface:
        """Returns:
            The process associated with this PteRun instance."""
        return self._proc

    @property
    def proc_layer(self) -> interfaces.layers.TranslationLayerInterface:
        """Returns:
            The layer for the process associated with this PTE."""
        if not self.proc:
            return None

        if self.ptenum_handle:
            proc_offset = self.proc.vol.offset
            if proc_offset in self.ptenum_handle._proc_layer_dict:
                return self.ptenum_handle._proc_layer_dict[proc_offset]
            else:
                layer_name = self.proc.add_process_layer()
                return self.ptenum_handle.context.layers[layer_name]

        if self._context:
            layer_name = self.proc.add_process_layer()
            return self._context.layers[layer_name]

        return None

    @property
    def vaddr(self) -> int:
        """Returns:
            The virtual address that resolved to this PTE."""
        return self._vaddr
    
    @property
    def pid(self) -> int:
        """Returns:
            The PID for the process associated with this PTE."""
        if not self.proc:
            return None
        return int(self.proc.UniqueProcessId)

    @property
    def length(self) -> int:
        """Returns the size of the described page."""
        return self._length

    @property
    def phys_offset(self) -> int:
        """The offset within the dumped RAM."""
        if self._TRANS_SWIZZLE_MASK and self.state == 'TRANS' and \
                not (self._TRANS_SWIZZLE_MASK & self.pte_value):
            return self._phys_offset & self._INVALID_TRANS_MASK

        return self._phys_offset

    @property
    def swap_offset(self) -> int:
        """The offset within the corresponding Pagefile."""
        # For an explanation, see comment in PteEnumerator._init_variables
        if self._swap_offset is None:
            return None

        if self._SOFT_SWIZZLE_MASK and \
                not (self._SOFT_SWIZZLE_MASK & self.pte_value):
            if self._swap_offset == self._INVALID_SWAP_OFFSET:
                return None
            else:
                return self._swap_offset & self._INVALID_SWAP_MASK

        return self._swap_offset

    @property
    def pagefile_idx(self) -> int:
        """The Pagefile number (there can be up to 16)."""
        return self._pagefile_idx

    @property
    def data_layer(self) -> interfaces.layers.TranslationLayerInterface:
        """The layer to read the page's content from."""
        return self._data_layer

    @property
    def pte_layer(self) -> interfaces.layers.TranslationLayerInterface:
        """The layer containing the PTE."""
        return self._pte_layer

    @property
    def pte_value(self) -> int:
        """Returns:
            This PTE's value."""
        return self._pte_value

    @property
    def pte_paddr(self) -> int:
        """Returns:
            The Physical (or pagefile) address of this PTE."""
        return self._pte_paddr

    @property
    def is_proto(self) -> bool:
        """is_proto is set for PrototypePTEs: PTEs not part of the MMU PTEs but
        belonging to _SUBSECTION objects."""
        return self._is_proto

    @cached_property
    def pfn(self) -> int:
        """Returns:
            The Page Frame Number for this PTE (if applicable)."""
        if self._phys_offset is None:
            return None
        return self._phys_offset >> \
            (self.ptenum_handle._PAGE_BITS if self.ptenum_handle else 12)


    def _set_modified_characteristics(self):
        # First we check if they have not been set already
        if self._has_proto_set is not None and \
                self._orig_pte_is_sub_ptr is not None and \
                self._orig_pte_value is not None:
            return
        
        if self.pfn is None or not self.ptenum_handle:
            return

        mod_chr_dict = \
            self.ptenum_handle._get_modified_page_characteristics(self.pfn)
        self._has_proto_set = mod_chr_dict['has_proto_set']
        self._orig_pte_value = mod_chr_dict['orig_pte']
        self._orig_pte_is_sub_ptr = mod_chr_dict['orig_pte_is_sub_ptr']


    @property
    def has_proto_set(self) -> bool:
        """has_proto_set is set for MMU PTEs that have the Prototype flag set
        in their MMPFN entry."""

        if self._has_proto_set is None:
            self._set_modified_characteristics()

        return self._has_proto_set


    @property
    def orig_pte_value(self) -> int:
        """Returns the OriginalPte value of the current page's MMPFN
        entry."""
        if self._orig_pte_value is None:
            self._set_modified_characteristics()

        # We currently need this value only for orig_pte_is_sub_ptr and also
        # only if the PrototypePte flag is set, so this value is only in this
        # case gathered and set through _set_modified_characteristics.
        return self._orig_pte_value


    @property
    def orig_pte_is_sub_ptr(self) -> bool:
        """Returns True if the OriginalPte state of the current page's MMPFN
        entry is _MMPTE_SUBSECTION. This means for pages belonging to mapped
        image files, that they are not yet modified."""
        if self._orig_pte_is_sub_ptr is None:
            self._set_modified_characteristics()

        return self._orig_pte_is_sub_ptr


    @property
    def is_proto_ptr(self) -> bool:
        """is_proto_ptr is set for MMU PTEs that either directly (PROTOPOINT)
        or indirectly (PROTOVAD) point to a Prototype PTE"""
        return self._is_proto_ptr

    @property
    def proto_ptr_run(self) -> PteRun:
        """If this PTE is a ProtoType PTE, there should be a proto-pointer PTE
        pointing to this PTE. This function returns this proto-pointer PTE."""
        return self._proto_ptr_run

    @property
    def ptenum_handle(self) -> PteEnumerator:
        """Returns:
            A handle to the PteEnumerator instance, this PTE has been
            initialized with.
            Note: Depending on the way PteEnumerator is used, this handle might
            have already been initialized for another process, so a call to 
            init_for_proc might be necessary.
            The other functions/properties of PteRun do already take this into
            account, so there is no special handling necessary.
        """
        return self._ptenum_handle

    @property
    def context(self) -> interfaces.context.ContextInterface:
        return self._context

    @property
    def state(self) -> str:
        """Returns:
            The PTE's state as string, according to state_enum_rev."""
        return state_enum_rev[self._state] if self._state else 'Undetermined'

    @property
    def pte_vaddr(self) -> int:
        """Returns:
            The virtual address of this PTE.

        Note: This value is currently only pre-set for prototype PTEs, so we
        resolve it dynamically upon call."""
        if self._pte_vaddr:
            return self._pte_vaddr
        
        if not self.ptenum_handle:
            vollog.warning("Without ptenum context, resolving the PTE's "
                           "virtual address is currently not supported.")
            return self._pte_vaddr

        if self._pte_paddr is None:
            return self._pte_vaddr

        _, pte_vaddr = self.ptenum_handle.ptov(self._pte_paddr)
        self._pte_vaddr = pte_vaddr
        return self._pte_vaddr

    @cached_property
    def is_executable(self) -> bool:
        """Returns:
            Whether or not the described page is executable."""
        # The prototype PTE can have a different protection value than the
        # mapped view in a process, so we first check for the protection of the
        # proto-pointer, as this protection supersedes the one of the prototype PTE.
        if self.is_proto and self._proto_ptr_run and \
                self._proto_ptr_run._is_exec is not None:
            return self._proto_ptr_run._is_exec
        
        return self._is_exec


    @property
    def is_data_available(self) -> bool:
        """Returns True if there is a readable physical page (from RAM), or
        if the page has been paged out and the corresponding Pagefile has been
        provided."""
        return bool((self.phys_offset is not None or
                     self.swap_offset is not None) and self.data_layer)

    @property
    def is_swapped(self) -> bool:
        """Returns:
            True if the page has been swapped to compressed memory/pagefile."""
        return self._state == 3

    @property
    def is_mapped(self) -> bool:
        """Returns:
            True if the page's state is HARDWARE or TRANSITION,
            otherwise False."""
        return self._state in [1, 2]


    @cached_property
    def is_unmodified_img_page(self) -> bool:
        """Returns:
            True if this page belongs to an image file and this page is yet
            not modified.
            False otherwise.
            It returns None if the page does not belong to an image file.
        """
        try:
            if PteEnumerator.vad_contains_image_file(self.get_vad()[2]):
                return self.orig_pte_is_sub_ptr
        except:
            pass
        return None
    

    @cached_property
    def is_empty(self) -> bool:
        """Checks if this page belongs to valid physical page and does not 
        contain only zeroes.
        
        Returns None if there is no physical page associated with this PteRun,
        True if the physical page consists only of null bytes and 
        False otherwise"""
        if not self.is_data_available:
            return None
        
        if self._length <= 0x1000 and self.ptenum_handle:
            return self.read() == self.ptenum_handle._ALL_ZERO_PAGE
        else:
            return self.read() == b"\x00" * self._length


    def get_mmpte(self) -> ObjectInterface:
        """Returns:
            A _MMPTE_$STATE instance according to this PteRun's state."""
        if not (self._pte_paddr is not None and self._state and self._pte_layer):
            return None

        if self.ptenum_handle:
            struct_string = \
                self.ptenum_handle.symbol_table + \
                constants.BANG + \
                state_to_mmpte[self._state]
            return self.ptenum_handle.context.object(
                struct_string,
                offset = self._pte_paddr,
                layer_name = self.pte_layer.name)

        else:
            return None


    def get_mmpfn_entry(self) -> ObjectInterface:
        """Returns:
            The MMPFN entry for this PteRun if it has an associated physical
            page."""
        if self._phys_offset is None:
            return None
        
        if self.ptenum_handle:
            return self.ptenum_handle.mmpfn_db[self.pfn]
            
        else:
            # TODO return entry with self.context
            return None


    @lru_cache(maxsize=64)
    def get_vad(self) -> Tuple[int, int, ObjectInterface]:
        """Returns:
            The VAD associated with this PteRun instance in a tuple:
            (vad_start, vad_end, MMVAD)"""
        if self.vaddr is None:
            return (None, None, None)

        if self.ptenum_handle:
            return self.ptenum_handle.get_vad_for_vaddr(self.vaddr, self.proc)

        else:
            for vad in self.proc.get_vad_root().traverse():
                vad_start = vad.get_start()
                vad_end = vad.get_end()
                if vad_start <= self.vaddr <= vad_end:
                    return (vad_start, vad_end, vad)
        return (None, None, None)


    def get_iso_pte(self) -> PteRun:
        if self.ptenum_handle:
            return self.ptenum_handle.resolve_iso_pte_by_vaddr(self.vaddr)
        return None


    def read(self, rel_off: int = None, length: int = None, **kwargs) -> bytes:
        """
        params:
            rel_off: Start reading at the given relative offset. 
            length: Only read "length" bytes.
            
        Returns:
            The page's content, described by this PteRun."""
        
        if rel_off is None:
            rel_off = 0
        
        if rel_off >= self.length:
            vollog.warning("Given relative offset is bigger than current page. "
                           "Resetting to 0.")
            rel_off = 0

        if length is None:
            length = self.length

        if (rel_off + length) > self.length:
            vollog.debug("Data to be read lies outside this page: "
                           f"rel_off: {rel_off:d} length: {length:d}. Fixing...")
            length = self.length - rel_off

        if not self.is_data_available and self.vaddr is not None:
            # We didn't find a corresponding physical/swap address, so we try a
            # last resort effort to get some data via Volatility.
            try:
                return self.proc_layer.read(self._vaddr + rel_off,
                                            length,
                                            **kwargs)
            except Exception:
                vollog.warning("No data found for Process {:d} at vaddr: "
                                "0x{:x}.".format(self.pid, self._vaddr))
                # For swapped pages, idx 0 is typically the first pagefile,
                # idx 1 the swapfile (if no further pagefile is active)
                # and idx 2 refers to the virtual store for compressed
                # memory: https://www.fireeye.com/blog/threat-research/2019/08/finding-evil-in-windows-ten-compressed-memory-part-two.html
                if self._pagefile_idx == 2:
                    vollog.warning("The page is most likely contained "
                                    "within compressed memory. Currently, "
                                    "there is no support for this in "
                                    "Volatility3.")
            return None

        offset = self._phys_offset if self._phys_offset is not None \
                                   else self.swap_offset
        offset += rel_off
        try:
            return self._data_layer.read(offset, length, **kwargs)
        except Exception:
            vollog.warning("Failed to retrieve data for Process {:d} at "
                           "vaddr: 0x{:x}.".format(self.pid, self._vaddr))
            return b''


    def __repr__(self) -> str:
        """Pretty printing PteRun instance."""
        result = "PteRun:\n"
        result += "PID: " + ("{:d}".format(self.pid) if isinstance(self.pid, int) else "Undetermined") + "\n"
        result += "vaddr: " + ("0x{:x}".format(self._vaddr) if isinstance(self._vaddr, int) else "None") + "\n"
        if self.is_swapped:
            result += "swap_offset: " + ("0x{:x}".format(self.swap_offset) if self.swap_offset is not None else "None") + "\n"
            result += "pagefile_idx: " + ("{:d}".format(self.pagefile_idx) if self.pagefile_idx is not None else "None") + "\n"
        else:
            result += "phys_offset: " + ("0x{:x}".format(self.phys_offset) if self.phys_offset is not None else "None") + "\n"
        result += "length: " + ("0x{:x}".format(self._length) if self._length else "None") + "\n"
        result += "pte_value: " + ("0x{:x}".format(self._pte_value) if isinstance(self._pte_value, int) else "None") + "\n"
        result += "pte_paddr: " + ("0x{:x}".format(self._pte_paddr) if isinstance(self._pte_paddr, int) else "None") + "\n"
        result += "pte_vaddr: " + ("0x{:x}".format(self.pte_vaddr) if isinstance(self.pte_vaddr, int) else "None") + "\n"
        result += "is_proto: {0}".format("Undetermined" if self._is_proto is None else self._is_proto) + "\n"
        result += "is_proto_ptr: {0}".format("Undetermined" if self._is_proto_ptr is None else self._is_proto_ptr) + "\n"
        result += "has_proto_set: {0}".format("Undetermined" if self.has_proto_set is None else self.has_proto_set) + "\n"
        result += "orig_pte_value: {0}".format("Undetermined" if self.orig_pte_value is None else "0x{:x}".format(self.orig_pte_value)) + "\n"
        result += "orig_pte_is_sub_ptr: {0}".format("Undetermined" if self.orig_pte_is_sub_ptr is None else self.orig_pte_is_sub_ptr) + "\n"
        result += "state: {0}".format(self.state) + "\n"
        result += "is_exec: {0}".format("Undetermined" if self._is_exec is None else self._is_exec) + "\n"
        if self.is_proto and self._proto_ptr_run:
            result += "Page is for this process executable: {0}".format(self.is_executable) + "\n"
            result += "\nProtopointer (the actual MMU PTE):\n"
            result += textwrap.indent(repr(self.proto_ptr_run), '    ')
        return result


    def get_full_string_repr(self) -> str:
        """Returns:
            The PteRun and MMPTE represantions for this PteRun, also for
        any potential proto-pointer."""
        result = "Internal PteRun representation:\n"
        result += "==============================\n"
        result += repr(self)
        result += "\n"
        mmpte = self.get_mmpte()
        if mmpte:
            result += "MMPTE struct:\n"
            result += "=============\n"
            result += repr(self.get_mmpte())
            if self.is_proto and self._proto_ptr_run:
                proto_mmpte = self.proto_ptr_run.get_mmpte()
                if proto_mmpte:
                    result += "\nCorresponding ProtoPointer:\n"
                    result += "---------------------------\n"
                    result += textwrap.indent(
                        repr(self.proto_ptr_run.get_mmpte()), '    ')
        result += "\n"
        return result


class SubsecProtoWrapper(object):
    """Helper class for enumerating all ProtoType PTEs of all Subsections
    associated with a given VAD, especially because the Prototype PTEs pointed
    to by vad.FirstPrototypePte do not always cover the whole memory area."""
    def __init__(self, vad, page_bits, pte_size, *args, **kwargs):
        self._PTE_SIZE = pte_size
        self._PAGE_BITS = page_bits
        self.range = None
        self.index_list = None
        if "Subsection" in vad.vol.members.keys():
            self.subsec = vad.Subsection
        self.is_last = False


    def _init_subsec(self) -> None:
        first_subsec = self.subsec.dereference()
        last = first_subsec.PtesInSubsection - 1
        self.range = [0, last]
        self.index_list = [(0, last, first_subsec)]


    def _calc_pteaddr(self, subsec: ObjectInterface, idx: int) -> int:
        return subsec.SubsectionBase + (idx * self._PTE_SIZE)

    def get_pteaddr_for_vaddr(self,
                              vad: ObjectInterface,
                              vad_start: int,
                              vad_end: int,
                              vaddr: int) -> int:
        # In most yet observed cases, the Subsection-PTEs are contiguous,
        # so while there are multiple Subsections, each one points with
        # their SubsectionBase pointer into a big contiguous array of PTEs.
        # This means that in those cases, the VAD covers all PTEs with its 
        # FirstPrototypePte and LastContiguousPte pointers. This way of
        # accessing PTEs is also way faster, since we don't have to walk
        # Subsections for every vaddr.
        # There are, however, cases, where not all PTEs are contiguous (e.g.
        # an open log file that gets larger).
        # In these cases we have to walk the Subsections in order to get
        # the correct PTE since it is not part of the contiguous PTEs,
        # referenced by the VAD.

        if vaddr > vad_end:
            vollog.warning("Given vaddr exceeds range of VAD: vaddr 0x{:x} "
                           "vadrange: 0x{:x} - 0x{:x}"
                           .format(vaddr, vad_start, vad_end)) 
            return None
        idx = (vaddr - vad_start) >> self._PAGE_BITS

        if "FirstPrototypePte" in vad.vol.members.keys():
            pte_addr = vad.FirstPrototypePte + (idx * self._PTE_SIZE)
            if pte_addr <= vad.LastContiguousPte:
                return pte_addr

        if not self.subsec:
            vollog.warning("No Subsection available for vaddr 0x{:x}, this "
                           "shouldn't happen.".format(vaddr))
            return None

        if not self.range:
            self._init_subsec()

        # As there might be subviews and hence, our PTE may not be referenced
        # by the contiguous pointers, we have to calculate the offset for those
        # cases.
        pointer_diff = old_div(
            (vad.FirstPrototypePte - self.index_list[0][2].SubsectionBase),
            self._PTE_SIZE)
        idx += pointer_diff
        if self.range[0] <= idx <= self.range[1]:
            for base_idx, end, subsec in self.index_list:
                if base_idx <= idx <= end:
                    return self._calc_pteaddr(subsec, idx - base_idx)
            vollog.info("No Subsection found for the given index: 0x{:x} "
                        "and vaddr: 0x{:x}. Potentially not yet populated "
                        "SUBSECTIONs for a growing file.".format(idx, vaddr)) 
            return None

        elif self.is_last:
            vollog.info("No Subsection found for the given index: 0x{:x} "
                        "and vaddr: 0x{:x}. Potentially not yet populated "
                        "SUBSECTIONs for a growing file.".format(idx, vaddr)) 
            return None
        # idx belongs to a subsection, we have not enumerated so far
        base_idx, last_idx, subsec = self.index_list[-1]
        curr_idx = last_idx + 1
        subsec = subsec.NextSubsection
        while subsec != 0:
            subsec = subsec.dereference()
            pte_count = subsec.PtesInSubsection
            last_idx = curr_idx + pte_count - 1
            self.index_list.append((curr_idx, last_idx, subsec))
            self.range[1] = last_idx
            if idx <= last_idx:
                return self._calc_pteaddr(subsec, idx - curr_idx)
            curr_idx += pte_count
            subsec = subsec.NextSubsection

        self.is_last = True        

        # Ending here means we didn't find the PTE for the given index.
        vollog.info("No Subsection found for the given index. "
                       "Index: 0x{:x}, last enumerated index: 0x{:x}, vaddr: "
                       "0x{:x}. Potentially not yet populated SUBSECTIONs "
                       "for a growing file.".format(idx, last_idx, vaddr))
        return None


    def get_all_subsec_pteaddr(self) -> Generator[int]:
        """Returns every PTE address for each subsection in the list."""
        if not self.range:
            self._init_subsec()

        for base_idx, last_idx, subsec in self.index_list:
            subsec_base = subsec.SubsectionBase
            pte_count = last_idx - base_idx + 1
            for idx in range(0, pte_count, 1):
                yield subsec_base + (idx * self._PTE_SIZE)

        # curr_idx is only been kept for index_list resp. get_pteaddr_for_vaddr
        curr_idx = last_idx + 1
        subsec = subsec.NextSubsection
        while subsec != 0:
            subsec = subsec.dereference()
            pte_count = subsec.PtesInSubsection
            subsec_base = subsec.SubsectionBase
            last_idx = curr_idx + pte_count - 1
            self.index_list.append((curr_idx, last_idx, subsec))
            self.range[1] = last_idx
            for idx in range(0, pte_count, 1):
                yield subsec_base + (idx * self._PTE_SIZE)
            curr_idx += pte_count
            subsec = subsec.NextSubsection


# We support versions 1 and 2
framework_version = constants.VERSION_MAJOR
if framework_version == 1:
    kernel_layer_name = 'primary'
elif framework_version == 2:
    kernel_layer_name = 'kernel'
else:
    # The highest major version we currently support.
    raise RuntimeError(f"Framework interface version {framework_version} is "
                        "currently not supported.")


class PteEnumerator(object):
    """This class allows to access and analyze all PTEs
    (MMU and Prototype PTEs) of a given process, by walking the paging
    structures."""

    _mmpfn_db_raw = None
    # class variable; decreases significantly RAM consumption in the context of
    # enumerate_ptes_for_processes
    _subsec_dict = dict()
    _resolved_dtbs = dict()
    _vad_dict = dict()
    _proc_layer_dict = dict()
    _protect_values = None

    def __init__(self, *args, **kwargs):
        self.dtb = None
        self.proc_layer = None
        self.phys_layer = None
        self._swap_layer_count = None
        self._swap_layer_base_str = None
        self._invalid_pte_mask = None
        self._valid_mask = 1
        self.arch_os = None
        self.arch_proc = None
        self._mmpte_size = None
        self._PAGE_BITS = None
        self.kernel = None
        self.proc = None
        self.pid = None
        self.is_wow64 = None
        # Reference to the vadlist for the current process.
        # In essence a pointer into _vad_dict.
        self._proc_vads = list()
        self._already_initialized = False
        # This is set correctly in _init_variables, and is here only
        # a just-in-case thing.
        self._highest_user_addr = 0x7ffffffeffff
        if kwargs:
            self.context = kwargs.get('context', None)
            self.config = kwargs.get('config', None)
            if 'proc' in kwargs:
                self.init_for_proc(kwargs['proc'])


    def _read_pte_value(self, layer, addr):
        pte = None
        try:
            pte_raw = layer.read(addr, self._PTE_SIZE)
            pte = struct.unpack('<Q', pte_raw)[0]
        except exceptions.InvalidAddressException:
            pass

        return pte


    # static implementation of get_protection from class MMVAD_SHORT
    @staticmethod
    def _get_protection(protect, protect_values, winnt_protections):
        """Get the VAD's protection constants as a string."""
        try:
            value = protect_values[protect]
        except IndexError:
            value = 0

        names = []
        for name, mask in winnt_protections.items():
            if value & mask != 0:
                names.append(name)

        return "|".join(names)


    @lru_cache(maxsize=32)
    def _get_subsec_protection(self, protect):
        if not self._protect_values:
             self._protect_values = vadinfo.VadInfo.protect_values(context = self.context,
                                                                   layer_name = self.kernel.layer_name,
                                                                   symbol_table = self.kernel.symbol_table_name)
        return self._get_protection(protect, self._protect_values, vadinfo.winnt_protections)


    @staticmethod
    def _get_subsec_for_vad(vad: ObjectInterface) -> ObjectInterface:
        if not "Subsection" in vad.vol.members:
            return None
        return vad.Subsection.dereference()
    

    @staticmethod
    def _get_ca_for_subsec(subsec: ObjectInterface) -> ObjectInterface:
        if not subsec:
            return None
        return subsec.ControlArea.dereference()


    @classmethod
    def _get_ca_for_vad(cls, vad: ObjectInterface) -> ObjectInterface:
        return cls._get_ca_for_subsec(cls._get_subsec_for_vad(vad))


    @staticmethod
    @args_not_valid
    def _get_fileptr_for_ca(control_area: ObjectInterface) -> ObjectInterface:
        if control_area.FilePointer.Value:
            return control_area.FilePointer
        return None


    @staticmethod
    @args_not_valid
    def _get_section_object_for_fileptr(file_ptr: ObjectInterface
                                       ) -> ObjectInterface:
        file_obj = file_ptr.dereference().cast("_FILE_OBJECT")
        
        if file_obj.SectionObjectPointer:
            return file_obj.SectionObjectPointer.dereference().cast(
                "_SECTION_OBJECT_POINTERS")

        return None


    @classmethod
    def vad_contains_data_file(cls, vad: ObjectInterface) -> bool:
        """Returns:
            True if the given VAD has a valid DataSectionObject pointer."""
        if not cls.vad_contains_image_file(vad) and \
                vad.get_private_memory() == 0:
            ca = cls._get_ca_for_vad(vad)
            file_ptr = cls._get_fileptr_for_ca(ca)
            sec_obj_poi = cls._get_section_object_for_fileptr(file_ptr)
            if sec_obj_poi:
                return ca.vol.offset == sec_obj_poi.DataSectionObject
        return False


    @staticmethod
    def _get_vad_type(vad: ObjectInterface) -> int:
        # this case happens for PTEs not belonging to any VAD (orphaned pages)
        if isinstance(vad, int):
            return -1

        if vad.has_member("u1") and vad.u1.has_member("VadFlags1") and vad.u1.VadFlags1.has_member("VadType"):
            return vad.u1.VadFlags1.VadType

        elif vad.has_member("u") and vad.u.has_member("VadFlags") and vad.u.VadFlags.has_member("VadType"):
            return vad.u.VadFlags.VadType

        elif vad.has_member("Core"):
            if (vad.Core.has_member("u1") and vad.Core.u1.has_member("VadFlags1")
                    and vad.Core.u1.VadFlags1.has_member("VadType")):
                return vad.Core.u1.VadFlags1.VadType

            elif (vad.Core.has_member("u") and vad.Core.u.has_member("VadFlags")
                    and vad.Core.u.VadFlags.has_member("VadType")):
                return vad.Core.u.VadFlags.VadType

        raise AttributeError("Unable to find the VadType member")


    @classmethod
    def vad_contains_image_file(cls, vad: ObjectInterface) -> bool:
        """Returns:
            True if the given VAD belongs to a mapped PE file."""
        if vad is None:
            return None
        return cls._get_vad_type(vad) == 2


    @classmethod
    def vad_contains_file(cls, vad: ObjectInterface) -> bool:
        """Returns:
            True if the given VAD has an associated file object."""
        if cls.vad_contains_image_file(vad):
            return True
        ca = cls._get_ca_for_vad(vad)
        if cls._get_fileptr_for_ca(ca):
            return True
        return False


    # taken from rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_pde_addr(self, pdpte_value, vaddr):
        if pdpte_value & self._valid_mask:
            return ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))


    # based on rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDPTEs(self, start=0, end=None):
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        if end is None:
            end = self._highest_user_addr
        for pml4e_index in range(0, 0x200):
            vaddr = pml4e_index << 39
            if vaddr > end:
                return

            next_vaddr = (pml4e_index + 1) << 39
            if start >= next_vaddr:
                continue

            pml4e_addr = ((self.dtb & 0xffffffffff000) |
                          ((vaddr & 0xff8000000000) >> 36))
            pml4e_value = self._read_pte_value(self.phys_layer, pml4e_addr)

            # TODO paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            if not pml4e_value & self._valid_mask:
                continue

            tmp1 = vaddr
            for pdpte_index in range(0, 0x200):
                vaddr = tmp1 + (pdpte_index << 30)
                if vaddr > end:
                    return

                next_vaddr = tmp1 + ((pdpte_index + 1) << 30)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PML4E
                # Bits 11:3 are bits 38:30 of the linear address
                pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                              ((vaddr & 0x7FC0000000) >> 27))

                pdpte_value = self._read_pte_value(self.phys_layer, pdpte_addr)

                # TODO paged out paging structures have valid bit unset,
                # but if the pagefile is supplied, we still could read it.
                if pdpte_value is None or not pdpte_value & self._valid_mask:
                    continue

                yield [vaddr, pdpte_value, pdpte_addr]


    # based on rekall-core/rekall/plugins/addrspaces/amd64.py
    def _get_available_PDEs(self, vaddr, pdpte_value, start=0, end=None):
        if end is None:
            end = self._highest_user_addr
        # This reads the entire PDE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!

        pde_table_addr = self._get_pde_addr(pdpte_value, vaddr)
        if pde_table_addr is None:
            return

        try:
            data = self.phys_layer.read(pde_table_addr, 8 * 0x200)
        except Exception:
            vollog.warning("Failure reading PDEs from PDE table address: "
                           "0x{:x}".format(pde_table_addr))
            return
        pde_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for pde_index in range(0, 0x200):
            vaddr = tmp2 + (pde_index << 21)
            if vaddr > end:
                return

            next_vaddr = tmp2 + ((pde_index + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = pde_table[pde_index]

            # TODO Paged out paging structures have valid bit unset,
            # but if the pagefile is supplied, we still could read it.
            # Currently, we skip PDE if it is not valid or not in transition.
            if not (pde_value & self._valid_mask or 
                    pde_value & self._proto_transition_mask ==
                    self._transition_mask):
                continue

            yield [vaddr, pde_table[pde_index], pde_table_addr + pde_index * 8]


    # based on rekall-core/rekall/plugins/windows/pagefile.py
    def _get_available_PTEs(self, pde_value, vaddr, start=0, end=None,
                            ignore_vad=False):
        """Scan the PTE table and yield address ranges which are valid."""
        if end is None:
            end = self._highest_user_addr

        base_phy_offset = pde_value & self._hard_pfn_mask
        pte_table_addr = base_phy_offset | ((vaddr & 0x1ff000) >> 9)

        # Invalid PTEs.
        if pte_table_addr is None:
            return

        # This reads the entire PTE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        try:
            data = self.phys_layer.read(pte_table_addr, self._PTE_SIZE * 0x200)
        except Exception:
            vollog.warning("Failure reading PTEs from PTE table address: "
                           "0x{:x}".format(pte_table_addr))
            return

        pte_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp = vaddr
        for i in range(0, len(pte_table)):
            pfn = i << 12
            pte_value = pte_table[i]

            vaddr = tmp | pfn
            if vaddr > end:
                return
            if start > vaddr:
                continue

            yield [vaddr, pte_value, pte_table_addr + i*8]


    @verify_initialized
    def enumerate_ptes(self,
                       start: int = 0,
                       end: int = None,
                       nx_ret: bool = False,
                       subsec_ret: bool = False,
                       zero_ret: bool = True) -> Generator[PteRun]:
        """Enumerates all Paging structures and returns a PteRun object for 
        each identified PTE.
        
        Without nx_ret set, this method tries to return all MMU PTEs, which
        can also result in "non-existent" PTEs being returned, since a demand
        zero PTE for a valid virtual address can't be differentiated from just
        null bytes in a Page Table (by just looking at the Page Table data),
        not related to any valid virtual address. (Well it could be, if we
        trust the VAD boundaries, but we don't want to do this.) Hence, these
        runs must be stripped on a higher layer, e.g. by simply stripping all
        SOFTZERO runs or by checking for an corresponding VAD.
        """

        # performance improvement in regards to PrototypePTE-flag checks
        self._ensure_mmpfn_db_raw()

        if end is None:
            end = self._highest_user_addr

        executable = None

        for pdpte_vaddr, pdpte_value, pdpte_addr in self._get_available_PDPTEs(start, end):
            if pdpte_vaddr & self._valid_mask and \
                    pdpte_value & self._page_size_mask:
                # huge page (1 GB)
                executable = False
                if not (pdpte_value & self._nx_mask):
                    executable = True
                elif nx_ret:
                    continue

                phys_offset = ((pdpte_value & self._hp_upper_mask) |
                               (pdpte_vaddr & self._hp_lower_mask))

                yield PteRun(self,
                             self.proc,
                             pdpte_vaddr,
                             length=self._HUGE_PAGE_SIZE,
                             phys_offset=phys_offset,
                             pte_value=pdpte_value,
                             is_proto=False,
                             is_proto_ptr=False,
                             is_exec=executable,
                             pte_paddr=pdpte_addr,
                             state=state_enum['HARD'],
                             # TODO paged out paging structures must be considered
                             data_layer=self.phys_layer,
                             pte_layer=self.phys_layer)
                continue

            for pde_vaddr, pde_value, pde_addr in self._get_available_PDEs(pdpte_vaddr, pdpte_value, start, end):
                if pde_value & self._valid_mask and \
                        pde_value & self._page_size_mask:
                    # large page
                    vollog.debug("Found large page at 0x{:x}".format(pde_vaddr))

                    executable = False
                    if not pde_value & self._nx_mask:
                        executable = True
                    elif nx_ret:
                        continue

                    phys_offset = ((pde_value & self._lp_upper_mask) |
                                   (pde_vaddr & self._lp_lower_mask))

                    yield PteRun(self,
                                 self.proc,
                                 pde_vaddr,
                                 length=self._LARGE_PAGE_SIZE,
                                 phys_offset=phys_offset,
                                 pte_value=pde_value,
                                 is_proto=False,
                                 is_proto_ptr=False,
                                 is_exec=executable,
                                 pte_paddr=pde_addr,
                                 state=state_enum['HARD'],
                                 # TODO paged out paging structures must be considered
                                 data_layer=self.phys_layer,
                                 pte_layer=self.phys_layer)
                    continue

                for vaddr, pte_value, pte_addr in self._get_available_PTEs(pde_value, pde_vaddr, start, end):
                    run = self.resolve_pte(vaddr,
                                           pte_value,
                                           pte_addr,
                                           nx_ret=nx_ret,
                                           subsec_ret=subsec_ret,
                                           zero_ret=zero_ret)
                    if run:
                        yield run


    @classmethod
    def enumerate_ptes_for_processes(
            cls,
            processes: Generator[ObjectInterface, None, None],
            context: interfaces.context.ContextInterface,
            config: interfaces.configuration.HierarchicalDict,
            progress_callback: Optional[constants.ProgressCallback] = None,
            start: int = 0,
            end: int = None,
            nx_ret: bool = False,
            subsec_ret: bool = False,
            zero_ret: bool = True) -> Generator[Tuple[ObjectInterface,
                                                    ObjectInterface,
                                                    List[PteRun]],
                                                None, None]:
        """A classmethod-wrapper around enumerate_ptes, which iterates over all
        given processes. For details see enumerate_ptes docstring.

        Returns:
            A tuple for each process, containing the process, a PteEnumerator
            instance for the process and the enumerated PteRun instances.
            (proc, ptenum, list(PteRun))
        """

        i_proc = 0
        procs = list(processes)
        len_procs = len(procs)

        # TODO add threading
        for proc in procs:
            ptenum = PteEnumerator(context=context, config=config, proc=proc)
            ptenum._ensure_mmpfn_db_raw()
            i_proc += 1

            if progress_callback:
                progress_callback(
                    (i_proc/len_procs) * 100,
                    "Enumerating page tables for Process {:d}"
                    .format(ptenum.pid))
            pte_runs = ptenum.enumerate_ptes(start=start, 
                                             end=end,
                                             nx_ret=nx_ret,
                                             subsec_ret=subsec_ret,
                                             zero_ret=zero_ret)
            yield (proc, ptenum, pte_runs)

        # enumerate_ptes takes care of calling _ensure_mmpfn_db_raw
        cls._release_mmpfn_db_raw()


    def _get_hardware_pfn_for_pte_value(self, pte_value: int) -> int:
        return (pte_value & self._hard_pfn_mask) >> self._hard_pfn_start


    def _get_transition_pfn_for_pte_value(self, pte_value: int) -> int:
        return (pte_value & self._trans_pfn_mask) >> self._trans_pfn_start


    def get_pfn_from_pte_value(self, pte_value: int) -> int:
        """Returns:
            PageFrameNumber for given PTE value."""
        if pte_value & self._valid_mask:
            return self._get_hardware_pfn_for_pte_value(pte_value)

        elif pte_value & self._proto_transition_mask == self._transition_mask:
            return self._get_transition_pfn_for_pte_value(pte_value)

        return None


    def get_phys_addr_from_pfn(self, pfn: int, vaddr: int) -> int:
        """Expects already cleaned PFN via _trans_pfn_mask or _hard_pfn_mask.
        
        Returns:
            Physical address for the given PageFrameNumber and virtual
            address."""
        return ((pfn << self._PAGE_BITS) | (vaddr & self._PAGE_BITS_MASK))


    def get_phys_addr_from_pte(self, pte_value: int, vaddr: int) -> int:
        """Returns:
            Physical address for the given PTE value and virtual address."""
        pfn = self.get_pfn_from_pte_value(pte_value)
        if not pfn:
            return None
        return self.get_phys_addr_from_pfn(pfn, vaddr)


    @lru_cache(maxsize=1024)
    def _is_demand_zero_pte(self, pte_value: int) -> bool:
        if pte_value is None or pte_value == 0:
            return True

        if self._soft_swizzle_mask and not (self._soft_swizzle_mask & pte_value):
            pte_value = pte_value & self._invalid_pte_mask_negated
        # Guard Pages or Demand Zero pages with a modified Protection.
        # These have only the _MMPTE_SOFTWARE.Protection field set.
        if not (pte_value & self._soft_protection_mask_negated):
            return True

        return False


    def _get_mmpfn_entry_raw(self, pfn: int) -> bytes:
        """Gathers MMPFN entry directly without any parsing of the structure
        by Volatility => Returns just a byte array.
        This significantly improves processing time when done for 100.000+ PFNs.
        """
        offset = (pfn * self._mmpfn_entry_size)
        end = offset + self._mmpfn_entry_size
        entry = None

        if PteEnumerator._mmpfn_db_raw:
            entry = PteEnumerator._mmpfn_db_raw[offset:end]
            if entry == self._empty_mmpfn_entry or entry == b'':
                return None
        else:
            try:
                entry = self.kernel_layer.read(
                    self.mmpfn_db.vol.offset + offset,
                    self._mmpfn_entry_size)
            except Exception:
                # MMPFN entry inaccessible
                return None

        return entry


    def _get_u4_member_raw(self, mmpfn_entry_raw):
        u4 = mmpfn_entry_raw[self._mmpfn_entry_u4_offset: \
                             self._mmpfn_entry_u4_offset + \
                             self._mmpfn_entry_u4_size]
        unpack_str = '<Q' if self._mmpfn_entry_u4_size == 8 else '<I'
        return struct.unpack(unpack_str, u4)[0]


    def _get_originalpte_member_raw(self, mmpfn_entry_raw):
        orig_pte = mmpfn_entry_raw[self._mmpfn_entry_origpte_offset: \
                                   self._mmpfn_entry_origpte_offset + \
                                   self._mmpfn_entry_origpte_size]
        unpack_str = '<Q' if self._mmpfn_entry_origpte_size == 8 else '<I'
        return struct.unpack(unpack_str, orig_pte)[0]


    @cache
    def _get_modified_page_characteristics(self, pfn) -> dict:
        mod_chr_dict = {'orig_pte': None, 'has_proto_set': None, 
                        'orig_pte_is_sub_ptr': None}

        mmpfn_entry = self._get_mmpfn_entry_raw(pfn)
        if mmpfn_entry is None:
            vollog.debug("No/empty MMPFN entry for PFN {:d}".format(pfn))
            return mod_chr_dict

        mod_chr_dict['has_proto_set'] = \
            self._is_prototypepte_set_for_mmpfn(mmpfn_entry)
        # if the PrototypePte flag is not set, there is normally no reason
        # to check the OriginalPte value for being a _MMPTE_SUBSECTION in
        # order to determine whether or not the page has been modified.
        # But since we retrieve the MMPFN entry anyways, we keep the values
        # right away for potential future use
        mod_chr_dict['orig_pte'] = \
            self._get_originalpte_member_raw(mmpfn_entry)
        mod_chr_dict['orig_pte_is_sub_ptr'] = \
            self._is_originalpte_subsec_ptr(mod_chr_dict['orig_pte'])

        return mod_chr_dict


    def _is_prototypepte_set_for_mmpfn(self, mmpfn_entry):
        u4 = self._get_u4_member_raw(mmpfn_entry)
        return bool(u4 & self._mmpfn_entry_protopte_mask)


    def _is_originalpte_subsec_ptr(self, orig_pte):
        return bool(not (orig_pte & self._valid_mask) and \
                    orig_pte & self._prototype_mask)


    def _get_mmpfn_pteframe_for_mmpfn_raw(self, mmpfn_entry_raw):
        """Retrieves u4.PteFrame from a raw MMPFN entry. See also
        _get_mmpfn_entry_raw."""
        u4 = self._get_u4_member_raw(mmpfn_entry_raw)
        return (u4 & self._mmpfn_pteframe_bit_mask) >> \
            self._mmpfn_pteframe_bit_offset


    def _get_mmpfn_pteaddr_for_mmpfn_raw(self, mmpfn_entry_raw):
        """Retrieves PteAddress from a raw MMPFN entry. See also
        _get_mmpfn_entry_raw."""
        pteAddr = mmpfn_entry_raw[self._mmpfn_entry_pteaddr_offset: \
                                  self._mmpfn_entry_pteaddr_offset + \
                                      self._mmpfn_entry_pteaddr_size]
        unpack_str = '<Q' if self._mmpfn_entry_pteaddr_size == 8 else '<I'
        return struct.unpack(unpack_str, pteAddr)[0]


    def _get_subsec_proto_wrapper_for_vad(self, vad):
        if not "Subsection" in vad.vol.members.keys():
            return None

        subsec = vad.Subsection.real
        sub_proto_wrp = None
        if subsec in self._subsec_dict:
            return self._subsec_dict[subsec]
        else:
            sub_proto_wrp = \
                SubsecProtoWrapper(vad, self._PAGE_BITS, self._PTE_SIZE)
            self._subsec_dict[subsec] = sub_proto_wrp

        return sub_proto_wrp


    def _get_protopte_addr_and_val_via_vad(self, vaddr: int):
        vad_start, vad_end, vad = self.get_vad_for_vaddr(vaddr)
        if not vad:
            return [None, None]

        sub_proto_wrp = self._get_subsec_proto_wrapper_for_vad(vad)
        if not sub_proto_wrp:
            return [None, None]

        pte_addr = sub_proto_wrp.get_pteaddr_for_vaddr(vad,
                                                       vad_start,
                                                       vad_end,
                                                       vaddr)
        pte_value = None
        # An empy pte_addr normally means that no Subsection for the given vaddr
        # was found. Potentially because of a not yet populated SUBSECTION for
        # a growing file.
        if pte_addr:
            pte_value = self._read_pte_value(self.kernel_layer, pte_addr)
        return [pte_addr, pte_value]


    def _parse_proto_pointer(self, vaddr, pte_addr, pte_value, nx_ret):
        executable = None
        state = None
        proto_vaddr = ((self._proto_protoaddress_mask & pte_value) >>
                         self._proto_protoaddress_start)
        proto_paddr = None
        if (proto_vaddr == self.proto_vad_identifier):
            state = state_enum['PROTOVAD']
            # We observed this state for mapped data files
            # with no Copy-On-Write.

            # For this special case, in order to gather the protection value,
            # _MMPTE_SOFTWARE must be applied.
            prot_value = self._get_soft_protection_value(pte_value)
            executable = self._protection_value_states_executable(prot_value)
            if not executable and nx_ret:
                return [None, None, None, None]

            proto_vaddr, proto_value = \
                self._get_protopte_addr_and_val_via_vad(vaddr)
            # We are only using physical PTE addresses internally
            try:
                if proto_vaddr:
                    proto_paddr = self.kernel_layer.translate(proto_vaddr)[0]
            except exceptions.PagedInvalidAddressException:
                # Prototype PTE is inaccessible
                pass

        else:
            state = state_enum['PROTOPOINT']
            if self._proto_swizzle_mask and \
                    not(pte_value & self._proto_swizzle_mask):
                proto_vaddr = proto_vaddr & self._invalid_proto_mask
            # The protection value is at a different offset for proto-pointers
            # (instances of _MMPTE_PROTOTYPE) than the others, so we can't use 
            # _get_soft_protection_value here.
            prot_value = self._get_proto_protection_value(pte_value)
            if prot_value != 0:
                executable = self._protection_value_states_executable(prot_value)

            if executable is False and nx_ret:
                return [None, None, None, None]

            try:
                proto_paddr = self.kernel_layer.translate(proto_vaddr)[0]
                proto_value = self._read_pte_value(self.phys_layer, proto_paddr)
            except Exception:
                # Prototype PTE inaccessible
                proto_paddr = proto_value = None
        
        pte_run = PteRun(self,
                         self.proc,
                         vaddr,
                         length=self._PAGE_SIZE,
                         pte_value=pte_value,
                         is_exec=executable,
                         is_proto=False,
                         is_proto_ptr=True,
                         pte_paddr=pte_addr,
                         state=state,
                         # TODO paged out paging structures must be considered
                         pte_layer=self.phys_layer)
        return [proto_paddr, proto_vaddr, proto_value, pte_run]


    @lru_cache(maxsize=64)
    @args_not_none
    def _protection_value_states_executable(self, protection_value):
        if protection_value in self._executable_prots:
            return True

        if protection_value > 0:
            return False

        return None


    @lru_cache(maxsize=1024)
    @args_not_none
    def _get_soft_protection_value(self, pte_value):
        return (pte_value & self._soft_protection_mask) \
                >> self._soft_protection_start


    @args_not_none
    def _get_proto_protection_value(self, pte_value):
        return (pte_value & self._proto_protection_mask) \
                >> self._proto_protection_start


    @args_not_none
    def _get_trans_protection_value(self, pte_value):
        return (pte_value & self._trans_protection_mask) \
                >> self._trans_protection_start


    @args_not_none
    def _get_subsec_protection_value(self, pte_value):
        return (pte_value & self._subsec_protection_mask) \
                >> self._subsec_protection_start


    def _check_for_protovad(self, pte_run):
        if pte_run.is_proto and pte_run.proto_ptr_run.state == 'PROTOVAD':
            vollog.warning("The given PTE value is a VAD-Prototype PTE pointer."
                           " It's not possible to fully resolve it without its "
                           "corresponding virtual address.")


    def _get_proc_for_pid(self, pid: int) -> ObjectInterface:
        """Mainly helper function the resolve_pte_by_* functions. Uses the
        pslist plugin and the given pid to return the associated process."""
        filter_func = pslist.PsList.create_pid_filter([pid])
        procs = list(
            pslist.PsList.list_processes(
                self.context,
                layer_name = self.kernel.layer_name,
                symbol_table = self.kernel.symbol_table_name,
                filter_func = filter_func))
        if len(procs) > 0:
            return procs[0]
        return None


    def _try_fix_pte_run(self, pte_run: PteRun) -> None:
        """Helper function for the resolve_pte_by_* functions. It tries to
        set the corresponding process and vaddr if they are still missing."""
        if pte_run.vaddr is None and pte_run.phys_offset is not None:
            # We try to get the virtual address with the resolved physical
            # offset
            pid, pte_run._vaddr = self.ptov(pte_run.phys_offset)
            if pte_run._proc is None and pid > 0:
                proc = self._get_proc_for_pid(pid)
                pte_run._proc = proc


    @args_not_none
    @verify_initialized
    def resolve_pte_by_pte_paddr(self, pte_paddr: int) -> PteRun:
        """Wrapper around resolve_pte, which ignores the vaddr and pte_vaddr
        arguments. For a complete PteRun result, resolve_pte should be used
        with all required arguments."""
        try:
            pte_value = self._read_pte_value(self.phys_layer, pte_paddr)
            pte_run = self.resolve_pte(None, pte_value, pte_paddr, zero_ret=False)
            pid, pte_vaddr = self.ptov(pte_paddr)
            if pid > 0:
                proc = self._get_proc_for_pid(pid)
                if proc:
                    pte_run._proc = proc
            self._try_fix_pte_run(pte_run)
            self._check_for_protovad(pte_run)
            return pte_run
        except Exception:
            return None

    @args_not_none
    @verify_initialized
    def resolve_pte_by_vaddr(self, vaddr, nx_ret=False, zero_ret=False):
        """Returns a PteRun instance for the given virtual address.
        Currently, simply a wrapper around enumerate_ptes."""
        # TODO when using this function intensively ( > 10000 ), enumerate_ptes
        # slows down and should be replaced by the following two lines:
        # pte_addr, pte_value = self._get_pte_addr_and_val_for_va(vaddr)
        # return self.resolve_pte(vaddr, pte_value, pte_addr)
        # Those two lines are, however, currently not used as
        # _get_pte_addr_and_val_for_va doesn't support large/huge pages yet.
        
        # enumerate_ptes requires an aligned address
        base_vaddr =  vaddr & 0xffffffffff000
        pte_runs = list(self.enumerate_ptes(start=base_vaddr, 
                                            end=vaddr,
                                            nx_ret=nx_ret,
                                            zero_ret=zero_ret))
        if pte_runs:
            if len(pte_runs) > 1:
                vollog.warning("enumerate_ptes returned multiple PteRuns for "
                               "a single virtual address. Shouldn't be the "
                               "case.")
            return pte_runs[0]
        return None


    @args_not_none
    @verify_initialized
    def resolve_pte_by_pte_vaddr(self,
                             pte_vaddr: int,
                             is_proto: bool = False,
                             vaddr: int = None) -> PteRun:
        """Wrapper around resolve_pte, which ignores the vaddr
        argument. For a complete PteRun result, resolve_pte should be used
        with all required arguments."""
        try:
            pte_paddr = self.proc_layer.translate(pte_vaddr)[0]
            pte_value = self._read_pte_value(self.phys_layer, pte_paddr)
            proto_ptr_run = None
            if is_proto:
                proto_ptr_run = PteRun(self,
                                        None,
                                        vaddr,
                                        is_proto=False)
            pte_run = self.resolve_pte(vaddr,
                                        pte_value,
                                        pte_paddr,
                                        pte_vaddr=pte_vaddr,
                                        zero_ret=False,
                                        is_proto=is_proto,
                                        proto_ptr_run=proto_ptr_run)
            self._try_fix_pte_run(pte_run)
            self._check_for_protovad(pte_run)
            return pte_run
        except Exception as e:
            vollog.debug(e)
            return None


    @args_not_none
    @verify_initialized
    def resolve_pte_by_pte_value(self,
                                 pte_value: int,
                                 is_proto: bool = False) -> PteRun:
        """Wrapper around resolve_pte, which ignores the vaddr and pte_paddr
        arguments. For a complete PteRun result, resolve_pte should be used
        with all required arguments."""
        try:
            if self.pid is None:
                self.pid = 0
            pte_run = self.resolve_pte(
                0, pte_value, None, zero_ret=False, is_proto=is_proto)
            self._try_fix_pte_run(pte_run)
            self._check_for_protovad(pte_run)
            return pte_run
        except Exception:
            return None


    @args_not_none
    @verify_initialized
    def resolve_iso_pte_by_vaddr(self, vaddr: int) -> PteRun:
        """Tries to resolve the given virtual address to a PteRun of the
        corresponding Image Section Object."""
        try:
            pte_addr, pte_value = self._get_protopte_addr_and_val_via_vad(vaddr)
            pte_paddr = self.proc_layer.translate(pte_addr)[0]
            return self.resolve_pte(vaddr,
                                    pte_value,
                                    pte_paddr,
                                    is_proto=True,
                                    pte_vaddr=pte_addr,
                                    zero_ret=False)
        except Exception:
            vollog.debug(f"{self.pid}-{self.proc_name} failed to get img_pte")

        return None


    def resolve_pte(self,
                    vaddr: int,
                    pte_value: int,
                    pte_paddr: int,
                    pte_vaddr: int = None,
                    is_proto: bool = None,
                    proto_ptr_run: PteRun = None,
                    nx_ret: bool = False,
                    subsec_ret: bool = False,
                    zero_ret: bool = True) -> PteRun:
        """This function returns a PteRun object for pages that are executable.
        It will, however, skip pages that have not yet been accessed, even if
        they would be executable once accessed."""

        pte_dbg_str = (f"ptenum.resolve_pte: resolving PID: {self.pid:d} " +
                       (f"VADDR: 0x{vaddr:x}" if vaddr else str(vaddr)))
        vollog.debug(pte_dbg_str + " PTE_VALUE: " + \
                     (f"0x{pte_value:x}" if pte_value else str(pte_value)))
        # is_proto_ptr is not set to True in here, but only 
        # in _parse_proto_pointer
        is_proto_ptr = False
        has_proto_set = None
        orig_pte_value = None
        orig_pte_is_sub_ptr = None
        length = self._PAGE_SIZE
        executable = None
        phys_addr = None
        state = None
        swap_offset = None
        pagefile_idx = None
        data_layer = None

        # If we analyze a prototype PTE and the protopointer would state
        # executable, we still return None here if the prototype PTE is
        # demand zero. This is the desired behavior, as the proto-pointer
        # indicates an unmodified page and there is no data to analyze anyway.
        #
        # The other case is a demand-zero MMU PTE, which we definitely skip
        # for nx_ret or zero_ret.
        if self._is_demand_zero_pte(pte_value):
            vollog.debug(pte_dbg_str + " is_demand_zero")
            if nx_ret or zero_ret:
                return None
            state = state_enum['SOFTZERO']
            prot_value = self._get_soft_protection_value(pte_value)
            executable = self._protection_value_states_executable(prot_value)
            # TODO for completeness sake, the protection could at this point
            # be taken from the VAD, event though there is nothing here to see

        # active page
        elif pte_value & self._valid_mask:
            vollog.debug(pte_dbg_str + " is_valid")
            if not (pte_value & self._nx_mask):
                executable = True
            elif nx_ret:
                return None
            else:
                executable = False

            data_layer = self.phys_layer
            if pte_value & self._page_size_mask:
                length = self._LARGE_PAGE_SIZE
                vollog.warning("A large or huge page at this point is not yet "
                               "fully supported, since we can't differentiate "
                               "between those two here at the moment. We'll "
                               "assume a large page, but this could be false. "
                               "vaddr: 0x{:x}".format(vaddr))
                               
            state = state_enum['HARD']
            pfn = self._get_hardware_pfn_for_pte_value(pte_value)
            phys_addr = self.get_phys_addr_from_pfn(pfn, vaddr or 0)

        # proto-pointer
        elif not is_proto and (pte_value & self._prototype_mask):
            vollog.debug(pte_dbg_str + " is_proto_pointer")
            proto_paddr, proto_vaddr, proto_value, proto_pte_run = \
                self._parse_proto_pointer(vaddr, pte_paddr, pte_value, nx_ret)

            if nx_ret and proto_pte_run is None:
                return None

            return self.resolve_pte(vaddr,
                                    proto_value,
                                    proto_paddr,
                                    pte_vaddr=proto_vaddr,
                                    is_proto=True,
                                    proto_ptr_run=proto_pte_run,
                                    nx_ret=nx_ret,
                                    subsec_ret=subsec_ret,
                                    zero_ret=zero_ret)

        # subsection
        elif is_proto and (pte_value & self._prototype_mask):
            if subsec_ret:
                return None
            vollog.debug(pte_dbg_str + " is_subsec")
            state = state_enum['SUBSEC']
            prot_value = self._get_subsec_protection_value(pte_value)
            executable = self._protection_value_states_executable(prot_value)
            if not executable and nx_ret:
                return None

            # Reaching this state means we are analyzing a prototype PTE which
            # is in a _MMPTE_SUBSECTION state: The corresponding page belongs
            # to a file on the filesystem and this page was once mapped in
            # memory but is not anymore. Furthermore this means that the page's
            # content either was not changed during runtime, or its content was
            # written back to the file (so it is now the same). Furthermore,
            # this state also means accessing it would require reading the file
            #
            # TODO add functionality to read the file, if it can be gathered

        # in transition
        elif pte_value & self._transition_mask:
            vollog.debug(pte_dbg_str + " is_transition")
            prot_value = self._get_trans_protection_value(pte_value)
            executable = self._protection_value_states_executable(prot_value)
            if not executable and nx_ret:
                return None

            state = state_enum['TRANS']
            data_layer = self.phys_layer
            pfn = self._get_transition_pfn_for_pte_value(pte_value)
            phys_addr = self.get_phys_addr_from_pfn(pfn, vaddr or 0)

        # pagefile PTE
        elif pte_value & self._soft_pagefilehigh_mask:
            vollog.debug(pte_dbg_str + " is_soft")
            state = state_enum['SOFT']
            prot_value = self._get_soft_protection_value(pte_value)
            executable = self._protection_value_states_executable(prot_value)
            if not executable and nx_ret:
                return None

            swap_offset = \
                (((pte_value & self._soft_pagefilehigh_mask)
                  >> self._soft_pagefilehigh_start)
                 << self._PAGE_BITS) | ((vaddr or 0) & self._PAGE_BITS_MASK)
            # The swizzle bit is handled within PteRun.
            # For an explanation, see comment in PteEnumerator._init_variables

            # Compressed memory has typically an index of 2
            pagefile_idx = \
                ((pte_value & self._soft_pagefilelow_mask)
                 >> self._soft_pagefilelow_start)

            if self._swap_layer_count > 0:
                try:
                    swap_layer_name = \
                        self._swap_layer_base_str + str(pagefile_idx)
                    data_layer = self.context.layers[swap_layer_name]
                except Exception:
                    # We don't have a swap_layer for this PTE = The pagefile
                    # hasn't been provided.
                    pass

        else:
            # unknown state
            vollog.debug(
                "Unknown PTE entry: PID: {:d}, PTE physical address: {:s}, "
                "value: 0x{:x}, value bin: {:s}, vaddr: {:s}, "
                "protoPTE: {}".format(
                    self.pid,
                    hex(pte_paddr) if pte_paddr is not None else "None",
                    pte_value, 
                    bin(pte_value),
                    hex(vaddr) if vaddr is not None else "None",
                    is_proto))

        if phys_addr:
            vollog.debug(pte_dbg_str + " has_pfn")
            pfn = phys_addr >> self._PAGE_BITS
            mod_chr_dict = self._get_modified_page_characteristics(pfn)
            has_proto_set = mod_chr_dict['has_proto_set']
            orig_pte_value = mod_chr_dict['orig_pte']
            orig_pte_is_sub_ptr = mod_chr_dict['orig_pte_is_sub_ptr']

        if is_proto:
            return PteRun(self,
                          self.proc,
                          vaddr,
                          length=length,
                          phys_offset=phys_addr,
                          pte_value=pte_value,
                          is_proto=is_proto,
                          has_proto_set=has_proto_set,
                          orig_pte_value=orig_pte_value,
                          orig_pte_is_sub_ptr=orig_pte_is_sub_ptr,
                          proto_ptr_run=proto_ptr_run,
                          is_proto_ptr=is_proto_ptr,
                          is_exec=executable,
                          pte_paddr=pte_paddr,
                          pte_vaddr=pte_vaddr,
                          state=state,
                          swap_offset=swap_offset,
                          pagefile_idx=pagefile_idx,
                          data_layer=data_layer,
                          # TODO paged out paging structures must be considered
                          pte_layer=self.phys_layer)

        else:
            return PteRun(self,
                          self.proc,
                          vaddr,
                          length=length,
                          phys_offset=phys_addr,
                          pte_value=pte_value,
                          is_proto=is_proto,
                          has_proto_set=has_proto_set,
                          orig_pte_value=orig_pte_value,
                          orig_pte_is_sub_ptr=orig_pte_is_sub_ptr,
                          is_proto_ptr=is_proto_ptr,
                          is_exec=executable,
                          pte_paddr=pte_paddr,
                          pte_vaddr=pte_vaddr,
                          state=state,
                          swap_offset=swap_offset,
                          pagefile_idx=pagefile_idx,
                          data_layer=data_layer,
                          # TODO paged out paging structures must be considered
                          pte_layer=self.phys_layer)


    # This is left just in case. It has been replaced by Volatility3's
    # already populated maximum_address for the physical layer.
    def _get_highest_phys_page_old(self) -> int:
        """This is a workaround to get MmHighestPhysicalPage, the highest
        physical page: last valid PFN entry.
        As this field does not seem to be set anymore in Windows 10's KDBG,
        the following function simply gets the phys_end field of the last
        _PHYSICAL_MEMORY_DESCRIPTOR Run, which should be equal to
        MmHighestPhysicalPage, and increments it by one.
        For details see "What makes it page" p. 495-496
        Note: We tested multiple Windows 7/10 VMs (x64) and at least did not
        encounter a PTE with a PFN higher than MmHighestPhysicalPage.

        Potential alternative: Get NumberOfPhysicalPages from _KUSER_SHARED_DATA
        Problem: As the physical address space also contains hardware reserved
        addresses, there are "holes" in this space and the highest physical page
        is typically larger than the amount of RAM. Hence, NumberOfPhysicalPages
        will not result in the last PFN DB entry. So we are not using it here.
        https://web.archive.org/web/20100330012524/http://blogs.technet.com/markrussinovich/archive/2008/07/21/3092070.aspx
        https://dfrws.org/sites/default/files/session-files/2013_USA_paper-anti-forensic_resilient_memory_acquisition.pdf
        """
        phys_mem_desc = self.kernel.get_symbol("MmPhysicalMemoryBlock").address
        phys_mem_desc = self.kernel.object(object_type = 'pointer',
                                           offset = phys_mem_desc)
        phys_mem_desc = phys_mem_desc.dereference()
        phys_mem_desc = phys_mem_desc.cast(
            self.kernel.symbol_table_name + constants.BANG + 
            "_PHYSICAL_MEMORY_DESCRIPTOR")

        phys_mem_run_type = self.kernel.get_type("_PHYSICAL_MEMORY_RUN")
        phys_mem_runs = phys_mem_desc.Run.cast(
            "array",
            count = phys_mem_desc.NumberOfRuns, 
            subtype = phys_mem_run_type)

        last_run = phys_mem_runs[-1]
        return last_run.BasePage + last_run.PageCount + 1


    def _get_pte_addr_and_val(self,
                              pfndbentry: ObjectInterface,
                              pfn: int) -> Tuple[int, int, bool, bool]:
        """Returns:
            pte_phys address and pte_value for a given MMPFN struct.
            It furthermore checks for a PTE pointer diff and returns the result.
            This function is currently only used for the PTE subversion and
            MAS remapping detection.
            (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)
        """
        containing_page = int(pfndbentry.u4.PteFrame)
        pte_offset = (int(pfndbentry.PteAddress) & 0xFFF)
        phys_pte_addr = (containing_page << self._PAGE_BITS) | pte_offset
        is_large_page = False
        pte_ptr_diff = False
        
        # Especially the first MMPFN instances tend to have a too large value
        # (0xff0000000000 would be 255 TB) in the PteFrame field.
        # Not sure about the reason yet. Potentially used for other purposes.
        if phys_pte_addr >= 0xff0000000000:
            return (None, None, is_large_page, pte_ptr_diff)

        # Kernel AS read_pte implementation uses the physical_address_space
        pte_value = self._read_pte_value(self.phys_layer, phys_pte_addr)
        if self.get_pfn_from_pte_value(pte_value) == pfn:
            # While the calculation for phys_pte_addr is different for large
            # pages (see _get_pte_addr_and_val_large), there are cases where
            # the "normal" calculation points to the correct PTE by accident.
            # So we check the PTE for actually being a large page:
            is_large_page =  \
                (pte_value & self._large_page_mask) == self._large_page_mask \
                and pte_value & self._valid_mask
            return (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)

        # MMPFN struct might belong to a large page
        tmp_phys_pte_addr, tmp_pte_value, is_large_page = \
            self._get_pte_addr_and_val_large(pfndbentry, pfn)
        if is_large_page:
            return (tmp_phys_pte_addr, tmp_pte_value, is_large_page, pte_ptr_diff)
        
        # It's not a large page, but still a PFN mismatch: SUSPICIOUS
        pte_ptr_diff = True
        return (phys_pte_addr, pte_value, is_large_page, pte_ptr_diff)


    # TODO add support for huge pages
    # CAUTION: The algorithm here is still experimental and must be evaluated
    # thoroughly.
    def _get_pte_addr_and_val_large(self,
                                    pfndbentry: ObjectInterface,
                                    pfn: int) -> Tuple[int, int, bool]:
        """Returns:
            pte_phys address and pte_value if the given MMPFN struct
            belongs to a large page, None otherwise.
            This function is currently only used for the PTE subversion and
            MAS remapping detection.
            (phys_pte_addr, pte_value, is_large_page)"""
        # TODO The following PteAddress calculation has only been tested on
        # Windows 10 x64 1511. E.g. in Windows 7 this works differently
        # (see "What makes it page" p.394) and should be added/tested.
        pte_offset = ((pfndbentry.PteAddress >> self._PAGE_BITS) & 
                      (self._PAGE_BITS_MASK >> 3))
        pte_offset <<= 3
        phys_pte_addr = (pfndbentry.u4.PteFrame << self._PAGE_BITS) | pte_offset
        pte_value = self._read_pte_value(self.phys_layer, phys_pte_addr)
        # Large pages are not paged out (see Windows Internals 7th Edition
        # Part 1, page 304), so the PTE should be valid.
        if not pte_value & self._valid_mask:
            return (None, None, False)

        # Each MMPFN struct for a given large page points to
        # the same PTE (PDE).
        first_pfn = self._get_hardware_pfn_for_pte_value(pte_value)
        last_pfn = first_pfn + old_div(self._LARGE_PAGE_SIZE, 0x1000) - 1
        if (pte_value & self._large_page_mask) == self._large_page_mask and \
                first_pfn <= pfn <= last_pfn:
            return (phys_pte_addr, pte_value, True)

        return (None, None, False)


    # taken from rekall-core/plugins/windows/pfn.py
    def ptov(self, physical_address: int) -> int:
        """Returns the PID and virtual address for the given physical address.
        
        However, resolving the PID is broken with newer Windows 10 versions, so
        there is no guarantee to get the PID."""
        pid = -1
        # TODO get dynamically
        table_names = ["Phys", "PTE", "PDE", "PDPTE", "PML4E", "DTB"]
        bit_divisions = [12, 9, 9, 9, 9, 4]

        # The physical and virtual address of the pte that controls the named
        # member.
        phys_addresses_of_pte = {}
        ptes = {}
        p_addr = physical_address

        # Starting with the physical address climb the PFN database in reverse
        # to reach the DTB. At each page table entry we store the its physical
        # offset. Then below we traverse the page tables in the forward order
        # and add the bits into the virtual address.
        for i, name in enumerate(table_names):
            pfn = p_addr >> self._PAGE_BITS
            mmpfn_entry_raw = self._get_mmpfn_entry_raw(pfn)
            if mmpfn_entry_raw is None:
                return [pid, None]

            # The PTE which controls this pfn.
            pte = self._get_mmpfn_pteaddr_for_mmpfn_raw(mmpfn_entry_raw)

            pteframe = self._get_mmpfn_pteframe_for_mmpfn_raw(mmpfn_entry_raw)
            # The physical address of the PTE.
            p_addr = ((pteframe << self._PAGE_BITS) |
                      (pte & self._PAGE_BITS_MASK))

            phys_addresses_of_pte[name] = p_addr

        # The DTB must be page aligned.
        dtb = p_addr & ~self._PAGE_BITS_MASK

        # Now we construct the virtual address by locating the offset in each
        # page table where the PTE is and deducing the bits covered within that
        # range.
        virtual_address = 0
        start_of_page_table = dtb

        for name, bit_division in reversed(list(zip(
                table_names, bit_divisions))):
            p_addr = phys_addresses_of_pte[name]
            pte_value = self._read_pte_value(self.phys_layer, p_addr)
            virtual_address += old_div((
                p_addr - start_of_page_table), self._mmpte_size)

            virtual_address <<= bit_division

            # The physical address where the page table begins. The next
            # iteration will find the offset of the next higher up page table
            # level in this table.
            start_of_page_table = \
                self._get_hardware_pfn_for_pte_value(pte_value) << self._PAGE_BITS

        virtual_address = virtual_address & self.kernel_layer.maximum_address
        virtual_address += physical_address & self._PAGE_BITS_MASK
        
        dtb_pfn = dtb >> 12
        if dtb_pfn in self._resolved_dtbs:
            return (self._resolved_dtbs[dtb_pfn], virtual_address)

        # only done once for each process, so no need 
        # to use _get_mmpfn_entry_raw here
        pfn_obj = self.mmpfn_db[dtb_pfn]
        # TODO at least starting with Windows 10 1803, mmpfn[dtb].u1.Flink
        # doesn't point to the EPROCESS anymore. This should be looked into.
        eproc = pfn_obj.u1.Flink.cast(
            self.kernel.symbol_table_name + constants.BANG + "pointer",
            subtype=self.kernel.get_type("_EPROCESS")
            ).dereference()
        try:
            pid = int(eproc.UniqueProcessId)
        except exceptions.PagedInvalidAddressException:
            pass
        self._resolved_dtbs[dtb_pfn] = pid
        return (pid, virtual_address)


    def init_for_proc(self, proc: ObjectInterface) -> None:
        """Initializes the current PteEnumerator for the given process. This
        function should normally be the first function to call."""
        self.proc = proc
        self.pid = int(proc.UniqueProcessId)
        self.proc_name = utility.array_to_string(proc.ImageFileName)
        self.dtb = int(proc.Pcb.DirectoryTableBase)
        proc_offset = proc.vol.offset
        if proc_offset not in self._vad_dict:
            self._vad_dict[proc_offset] = list()
            for vad in proc.get_vad_root().traverse():
                self._vad_dict[proc_offset].append(
                    (vad.get_start(), vad.get_end(), vad))
                    # (vad.get_start(), vad.get_end(), vad, PteEnumerator.vad_contains_image_file(vad)))
        self._proc_vads = self._vad_dict[proc_offset]

        self._initialize_internals()
        self._set_proc_layer()

        # used for the disassembler
        self.arch_proc = self.arch_os.lower()
        self.is_wow64 = self.proc.get_is_wow64()
        if self.is_wow64 and self.arch_os == "Intel64":
            self.arch_proc = "intel"


    def _initialize_internals(self) -> None:
        if self._already_initialized:
            return

        if framework_version == 1:
            layer_name = self.config[kernel_layer_name]
            kvo = self.context.layers[layer_name].config['kernel_virtual_offset']
            self.symbol_table = self.config['nt_symbols']

            self.kernel = self.context.module(self.symbol_table, 
                                              layer_name = layer_name,
                                              offset = kvo)
        else:
            self.kernel = self.context.modules[self.config[kernel_layer_name]]
            if 'nt_symbols' in self.config:
                self.symbol_table = self.config['nt_symbols']
            else:
                self.symbol_table = self.kernel.symbol_table_name

        self.kernel_layer = self.context.layers[self.kernel.layer_name]

        self.arch_os = self.kernel_layer.metadata.get("architecture")
        if self.arch_os != "Intel64":
            err_msg = ("This architecture is not yet supported: {:s}"
                       .format(self.arch_os))
            vollog.error(err_msg)
            raise RuntimeError(err_msg)

        vers = info.Info.get_version_structure(self.context,
                                               self.kernel.layer_name,
                                               self.kernel.symbol_table_name)
        self._kernel_build = int(vers.MinorVersion)

        # Used for pretty-printing MMPTE structs
        for state in state_to_mmpte.values():
            self.context.symbol_space[self.symbol_table].set_type_class(state, MMPTE)

        self._init_masks()
        self._init_enums()
        self._init_variables()
        self._already_initialized = True

    @staticmethod
    def _get_start_and_bitmask(member):
        start = member.vol.start_bit
        bitlength = member.vol.end_bit - member.vol.start_bit
        mask = ( ((1 << bitlength) - 1) << start )
        return (start, mask)


    # https://i.blackhat.com/USA-19/Thursday/us-19-Sardar-Paging-All-Windows-Geeks-Finding-Evil-In-Windows-10-Compressed-Memory-wp.pdf
    # taken from https://github.com/volatilityfoundation/volatility3/pull/772
    def _get_invalid_pte_mask(self):
        if self.kernel.has_symbol("MiInvalidPteMask"):
            pte_type = "unsigned int"
            if self._PTE_SIZE == 8:
                pte_type = "unsigned long long"

            return self.kernel.object(
                pte_type, 
                offset=self.kernel.get_symbol("MiInvalidPteMask").address)

        if self.kernel.has_symbol("MiState"):
            system_information = self.kernel.object(
                "_MI_SYSTEM_INFORMATION",
                offset=self.kernel.get_symbol("MiState").address)
            if system_information.Hardware.has_member('InvalidPteMask'):
                return system_information.Hardware.InvalidPteMask

        return 0


    def _init_masks(self):
        # These structs have especially changed within Windows 10, so we
        # gather the struct member offsets/masks dynamically.
        soft_pte = self.kernel.get_type("_MMPTE_SOFTWARE")
        page_low = soft_pte.vol.members['PageFileLow'][1]
        self._soft_pagefilelow_start, self._soft_pagefilelow_mask = \
            self._get_start_and_bitmask(page_low)
        page_high = soft_pte.vol.members['PageFileHigh'][1]
        self._soft_pagefilehigh_start, self._soft_pagefilehigh_mask = \
            self._get_start_and_bitmask(page_high)
        soft_prot = soft_pte.vol.members['Protection'][1]
        self._soft_protection_start, self._soft_protection_mask = \
            self._get_start_and_bitmask(soft_prot)
        self._soft_protection_mask_negated = \
            ((1 << 64) - 1) ^ self._soft_protection_mask

        if (soft_pte.has_member('SwizzleBit')):
            soft_swizzle = soft_pte.vol.members['SwizzleBit'][1]
            # The swizzle mask is used to test for the SwizzleBit to be set.
            _, self._soft_swizzle_mask = \
                self._get_start_and_bitmask(soft_swizzle)
            PteRun._SOFT_SWIZZLE_MASK = self._soft_swizzle_mask
        else:
            self._soft_swizzle_mask = None

        proto_pte = self.kernel.get_type("_MMPTE_PROTOTYPE")
        proto_bit = proto_pte.vol.members['Prototype'][1]
        _, self._prototype_mask = self._get_start_and_bitmask(proto_bit)
        proto_addr = proto_pte.vol.members['ProtoAddress'][1]
        self._proto_protoaddress_start, self._proto_protoaddress_mask = \
            self._get_start_and_bitmask(proto_addr)
        proto_prot = proto_pte.vol.members['Protection'][1]
        self._proto_protection_start, self._proto_protection_mask = \
            self._get_start_and_bitmask(proto_prot)

        if (proto_pte.has_member('SwizzleBit')):
            proto_swizzle = proto_pte.vol.members['SwizzleBit'][1]
            _, self._proto_swizzle_mask = \
                self._get_start_and_bitmask(proto_swizzle)
        else:
            self._proto_swizzle_mask = None
            self._invalid_proto_offset = None
            self._invalid_proto_mask = None

        subsec_pte = self.kernel.get_type("_MMPTE_SUBSECTION")
        subsec_prot = subsec_pte.vol.members['Protection'][1]
        self._subsec_protection_start, self._subsec_protection_mask = \
            self._get_start_and_bitmask(subsec_prot)

        trans_pte = self.kernel.get_type("_MMPTE_TRANSITION")
        trans_bit = trans_pte.vol.members['Transition'][1]
        _, self._transition_mask = \
            self._get_start_and_bitmask(trans_bit)
        trans_prot = trans_pte.vol.members['Protection'][1]
        self._trans_protection_start, self._trans_protection_mask = \
            self._get_start_and_bitmask(trans_prot)
        trans_pfn = trans_pte.vol.members['PageFrameNumber'][1]
        self._trans_pfn_start, _ = self._get_start_and_bitmask(trans_pfn)

        if (trans_pte.has_member('SwizzleBit')):
            trans_swizzle = trans_pte.vol.members['SwizzleBit'][1]
            _, self._trans_swizzle_mask = \
                self._get_start_and_bitmask(trans_swizzle)
            PteRun._TRANS_SWIZZLE_MASK = self._trans_swizzle_mask
        else:
            self._trans_swizzle_mask = None

        hard_pte = self.kernel.get_type("_MMPTE_HARDWARE")
        nx_bit = hard_pte.vol.members['NoExecute'][1]
        _, self._nx_mask = self._get_start_and_bitmask(nx_bit)
        large_bit = hard_pte.vol.members['LargePage'][1]
        self._page_size_mask = self._large_page_mask = \
            self._get_start_and_bitmask(large_bit)[1]
        hard_pfn = hard_pte.vol.members['PageFrameNumber'][1]
        self._hard_pfn_start, _ = self._get_start_and_bitmask(hard_pfn)

        # used to check for only the transition bit set, but not the proto bit
        self._proto_transition_mask = self._prototype_mask | self._transition_mask
        # Some masks are initialized later. See _init_variables


    def _init_enums(self):
        self._executable_prots = \
            [x for x, y in mm_prot_enum.items() if 'EXEC' in y]
        self._writable_prots = \
            [x for x, y in mm_prot_enum.items() if 'WRITE' in y]

    def _init_variables(self):
        self.phys_layer = self.context.layers['memory_layer']
        self._swap_layer_count = \
            self.kernel_layer.config['swap_layers.number_of_elements']
        if self._swap_layer_count > 0:
            # Get all swap_layer names, while taking into account, that these
            # names are not guaranteed to be stay the same accross different
            # volatility versions.
            temp = \
                [x[12:-9] for x in self.kernel_layer.config.keys()
                 if x.startswith('swap_layers.') and x.endswith('.location')][0]
            # There are at max 16 pagefiles, so the swap_layer number ranges
            # from 0 to 15, and we expect the number as the last part of the
            # swap_layer string.
            idx = -2 if temp[-2:].isdigit() else -1
            self._swap_layer_base_str = temp[:idx]

        if self.arch_os == "Intel64":
            self.proto_vad_identifier = 0xffffffff0000

        elif self.arch_os == "Intel32":
            # TODO add support for x86
            self.proto_vad_identifier = 0xffffffff
            vollog.error("Unsupported architecture: {:s}".format(self.arch_os))
            raise RuntimeError("Unsupported architecture")

        else:
            vollog.error("Unsupported architecture: {:s}".format(self.arch_os))
            raise RuntimeError("Unsupported architecture")

        self._PAGE_BITS = self.kernel_layer._page_size_in_bits
        PteRun._PAGE_BITS = self._PAGE_BITS
        self._PAGE_SIZE = 1 << self._PAGE_BITS
        self._PAGE_BITS_MASK = self._PAGE_SIZE - 1
        self._PTE_SIZE = self.kernel.get_type("_MMPTE_HARDWARE").vol.size
        # The empty page test uses this a lot, so we keep it once
        self._ALL_ZERO_PAGE = b"\x00" * self._PAGE_SIZE
        # large and huge pages will probably not occur that often,
        # and since they take significant amount of memory,
        # we don't keep them in memory
        
        # TODO retrieve dynamically
        self._LARGE_PAGE_SIZE = 0x200000
        self._LARGE_ARM_PAGE_SIZE = self._LARGE_PAGE_SIZE * 2
        self._HUGE_PAGE_SIZE = 0x40000000
        
        try:
            highest_user_addr = self.kernel.get_symbol("MmHighestUserAddress").address
            self._highest_user_addr = int(self.kernel.object(object_type = 'unsigned long long', offset = highest_user_addr))
        except exceptions.SymbolError:
            # Static fallback
            is_64bit_arch = symbols.symbol_table_is_64bit(
                self.context, self.kernel.symbol_table_name)
            if is_64bit_arch:
                self._highest_user_addr = 0x7ffffffeffff
            else:
                self._highest_user_addr = 0x7ffeffff

        mmpte_type = self.kernel.get_type("_MMPTE")
        self._mmpte_size = mmpte_type.vol.size
        # getting PFN DB
        self._hpp = self.phys_layer.maximum_address >> self._PAGE_BITS

        # PTEs in transition state also have a swizzle bit on newer Windows
        # versions and we have support for it. The logic is, however, currently
        # "overruled" anyways, since the usage of MAXPHYADDR gets rid of the
        # upper bits.
        # See below for more details.
        #
        # Actually, MAXPHYADDR could be 52 (depending on Intel documentation),
        # respectively 48 when going with Microsofts definition of
        # _MMPTE_HARDWARE resp. _MMPTE_TRANSITION and their PFN field.
        # It seems, however, that since at least Windows 10 1909, the
        # PageFrameNumber field for Transition PTEs uses the SwizzleBit field,
        # which affects the PFN's bit 33 (counting from zero, with a total
        # of 36 bits). In relation to the whole PTE, this means bit 45. 
        # Currently, we simply ignore the three most significant bits
        # altogether by setting MAXPHYADDR to 45. See also
        # https://github.com/volatilityfoundation/volatility3/pull/475
        # This shouldn't be a problem as long as the flags are not influencing
        # the actual PFN (so far, doesn't seem to be the case), and the
        # RAM size doesn't reach 32 TB:
        # ((2**(36 - 3)) * 0x1000) / (1024 * 1024 * 1024 * 1024)
        # Currently the max supported phys limit should be 24TB
        # https://docs.microsoft.com/en-us/windows/win32/memory/memory-limits-for-windows-releases
        # See intel system programming guide
        self._maxphyaddr = self.kernel_layer._maxphyaddr
        # Mask for the virtual address part of a huge page
        self._hp_lower_mask = (1 << 30) - 1
        # Mask for the PDPTE part of a huge page
        self._hp_upper_mask = ((1 << self._maxphyaddr) - 1) ^ self._hp_lower_mask
        # Mask for the virtual address part of a large page
        self._lp_lower_mask = (1 << 21) - 1
        # Mask for the PDE part of a large page
        self._lp_upper_mask = ((1 << self._maxphyaddr) - 1) ^ self._lp_lower_mask

        self._trans_pfn_mask = ((1 << self._maxphyaddr) -1)
        self._trans_pfn_mask ^= (1 << self._trans_pfn_start) - 1
        # with MAXPHYADDR = 45 : 0x1ffffffff000

        # same as self._trans_pfn_mask but kept separate in case of future changes
        self._hard_pfn_mask = ((1 << self._maxphyaddr) -1)
        self._hard_pfn_mask ^= (1 << self._hard_pfn_start) - 1

        # The swizzle bit indicates if a specific bit of the PTE value has to be
        # flipped.
        # See the whitepaper "Extracting Compressed Pages from the Windows 10
        # Virtual Store" (also known as "Finding Evil in Windows 10 Compressed
        # Memory") by Omar Sardar and Dimiter Andonov for further details.
        # https://i.blackhat.com/USA-19/Thursday/us-19-Sardar-Paging-All-Windows-Geeks-Finding-Evil-In-Windows-10-Compressed-Memory-wp.pdf
        if self._soft_swizzle_mask:
            self._invalid_pte_mask = self._get_invalid_pte_mask()
            self._invalid_pte_mask_negated = \
                ((1 << 64) - 1) ^ self._invalid_pte_mask
            PteRun._INVALID_SWAP_OFFSET = \
                ((self._invalid_pte_mask >> self._soft_pagefilehigh_start)
                << self._PAGE_BITS)
            PteRun._INVALID_SWAP_MASK = \
                ((1 << 64) - 1) ^ PteRun._INVALID_SWAP_OFFSET
            PteRun._INVALID_TRANS_OFFSET = \
                ((self._invalid_pte_mask >> self._trans_pfn_start)
                << self._PAGE_BITS)
            PteRun._INVALID_TRANS_MASK = \
                ((1 << 64) - 1) ^ PteRun._INVALID_TRANS_OFFSET

        if self._proto_swizzle_mask:
            if self._invalid_pte_mask is None:
                self._invalid_pte_mask = self._get_invalid_pte_mask()
            self._invalid_proto_offset = \
                self._invalid_pte_mask >> self._proto_protoaddress_start
            self._invalid_proto_mask = \
                ((1 << 64) - 1) ^ self._invalid_proto_offset

        self.mmpfn_db = self.kernel.get_symbol("MmPfnDatabase").address
        self.mmpfn_db = self.kernel.object(
            object_type = 'pointer',
            offset = self.mmpfn_db,
            subtype = self.kernel.get_type("pointer"))
        self.mmpfn_db = self.mmpfn_db.dereference()
        self.mmpfn_db = self.mmpfn_db.cast(
            "array", count = self._hpp,
            subtype = self.kernel.get_type("_MMPFN"))

        # Setting up variables for fast MMPFN access
        temp_pfn_entry = self.mmpfn_db[0]
        self._mmpfn_entry_size = temp_pfn_entry.vol.size
        self._empty_mmpfn_entry = b'\x00' * self._mmpfn_entry_size

        self._mmpfn_entry_u4_offset = temp_pfn_entry.vol.members['u4'][0]
        self._mmpfn_entry_u4_size = temp_pfn_entry.u4.vol.size
        self._mmpfn_entry_origpte_offset = \
            temp_pfn_entry.vol.members['OriginalPte'][0]
        self._mmpfn_entry_origpte_size = temp_pfn_entry.OriginalPte.vol.size
        mmpfn_entry_proto_offset = \
            temp_pfn_entry.u4.PrototypePte.vol.start_bit
        self._mmpfn_entry_protopte_mask = 1 << mmpfn_entry_proto_offset

        self._mmpfn_pteframe_bit_offset = \
            temp_pfn_entry.u4.PteFrame.vol.start_bit
        self._mmpfn_pteframe_bit_length = \
            temp_pfn_entry.u4.PteFrame.vol.end_bit - \
            self._mmpfn_pteframe_bit_offset
        self._mmpfn_pteframe_bit_mask = \
            (1 << self._mmpfn_pteframe_bit_length) - 1

        self._mmpfn_entry_pteaddr_offset = \
            temp_pfn_entry.vol.members['PteAddress'][0]
        self._mmpfn_entry_pteaddr_size = temp_pfn_entry.PteAddress.vol.size


    @verify_initialized
    def _ensure_mmpfn_db_raw(self):
        """Accessing 100.000 and more PFN DB entries is very time consuming, so
        we read the whole DB at once and access entries from within this blob.
        Currently this is only used for the PTE enumeration."""
        if PteEnumerator._mmpfn_db_raw is None:
            PteEnumerator._mmpfn_db_raw = self.kernel_layer.read(
                self.mmpfn_db.vol.offset, self._mmpfn_entry_size * self._hpp,
                pad=True)


    @classmethod
    def _release_mmpfn_db_raw(cls) -> None:
        """Frees the reference and hence the memory used for the MMPFN DB."""
        cls._mmpfn_db_raw = None


    def get_vad_for_vaddr(self,
                          vaddr: int,
                          proc: ObjectInterface = None,
                          supress_warning: bool = False
                          ) -> Tuple[int, int, ObjectInterface]:
        """Searches the internal vadlist for the given vaddr and returns the
        containing VAD.
        Returns:
            (vad_start, vad_end, VAD)"""
        if proc is None:
            proc_vads = self._proc_vads
            proc = self.proc
        else:
            proc_vads = self._vad_dict[proc.vol.offset]

        for start, end, vad in proc_vads:
            if start <= vaddr <= end:
                return (start, end, vad)
        warning_string = ("No VAD found for process {:d} and address 0x{:x}. "
                          "This could indicate hidden pages or a yet unknown "
                          "case."
                          .format(proc.UniqueProcessId, vaddr))
        if supress_warning:
            vollog.info(warning_string)
        else:
            vollog.warning(warning_string)
        return (None, None, None)


    def _set_proc_layer(self):
        """Assumes self.proc to be already set. This function should only
        be called from within init_for_proc."""
        proc_offset = self.proc.vol.offset
        if proc_offset in self._proc_layer_dict:
            self.proc_layer = self._proc_layer_dict[proc_offset]
            return

        layer_name = self.config[kernel_layer_name] + "_Process" + \
                     str(self.proc.UniqueProcessId)
        if layer_name not in self.context.layers:
            layer_name = self.proc.add_process_layer()

        self._proc_layer_dict[proc_offset] = self.context.layers[layer_name]
        self.proc_layer = self.context.layers[layer_name]


    # CAUTION: This algorithm doesn't work for large/huge pages
    def _get_pte_addr_and_val_for_va(self, vaddr):
        """Returns for a given virtual address its PTE's address and value.
        CAUTION: This algorithm doesn't work for large/huge pages.
        
        This function is currently only used for the PTE subversion and
        MAS remapping detection.
        """

        # For details on the algorithm see "What makes it page" p. 65 ff
        # make room for the PML4 auto-entry index
        pte_addr = vaddr >> 9
        # PTE entries are 8 byte aligned
        pte_addr = pte_addr &~ 0b111
        
        # set the leftmost 16 bits to 1
        pte_addr |= ( (0x10000-1) << 48)

        # clear the PML4 index
        pte_addr = pte_addr &~ ( (0x200-1) << 39 )
        
        # set the PML4 index to the PML4 Auto-entry
        pte_addr |= ( 0x1ed << 39 )
        
        pte_value = self._read_pte_value(self.proc_layer, pte_addr)
        try:
            pte_addr = self.proc_layer.translate(pte_addr)[0]
        except Exception:
            pte_addr = None
        return [pte_addr, pte_value]
