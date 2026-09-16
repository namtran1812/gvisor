// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build arm64
// +build arm64

package usertrap

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

// trapNR is the maximum number of traps what can fit in the trap table.
const trapNR = 256

// trapSize is the size of one trap.
const trapSize = 80

const (
	tableVMAName                = "[usertrap]"
	arm64TableMagic             = uint32(0x41555452)
	arm64TableVersion           = uint32(1)
	maxTrapTableMappingAttempts = uint64(64)
)

// TrapTableSize returns the maximum size of a trap table.
func TrapTableSize() uintptr {
	return uintptr(trapNR * trapSize)
}

type memoryManager interface {
	usermem.IO
	MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error)
	MUnmap(ctx context.Context, addr hostarch.Addr, length uint64) error
	FindVMAByName(ar hostarch.AddrRange, name string) (hostarch.Addr, uint64, error)
}

// State represents the current state of the trap table.
//
// +stateify savable
type State struct {
	mu sync.RWMutex `state:"nosave"`

	// tables is reconstructed from usertrap VMAs after fork or restore.
	tables []trapTable `state:"nosave"`
}

// trapTable is the in-memory allocation state for one ARM64 usertrap VMA.
// The VMA header is authoritative across fork and restore; this structure is
// only a runtime cache.
type trapTable struct {
	addr     hostarch.Addr
	nextTrap uint32
}

// +marshal
type header struct {
	magic    uint32
	version  uint32
	nextTrap uint32
}

func (h header) valid() bool {
	return h.magic == arm64TableMagic &&
		h.version == arm64TableVersion &&
		h.nextTrap >= 1 &&
		h.nextTrap <= trapNR
}

// New returns the new state structure.
func New() *State {
	return &State{}
}

func trapTableMappingSize() uint64 {
	size := uint64(TrapTableSize())
	return (size + uint64(hostarch.PageSize) - 1) &^ (uint64(hostarch.PageSize) - 1)
}

// loadUsertrap maps a new ARM64 trap table at addr without replacing any
// existing application mapping.
func loadUsertrap(ctx context.Context, mm memoryManager, addr hostarch.Addr) error {
	size := trapTableMappingSize()
	mapped, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:    size,
		Addr:      addr,
		Fixed:     true,
		NoReplace: true,
		Private:   true,
		Name:      tableVMAName,
		MLockMode: memmap.MLockEager,
		Perms:     hostarch.Read | hostarch.Execute,
		MaxPerms:  hostarch.AnyAccess,
	})
	if err != nil {
		return err
	}
	if mapped != addr {
		return fmt.Errorf("ARM64 usertrap mapped at %x, requested %x", mapped, addr)
	}
	return nil
}

func (t *trapTable) trapAddr(trap uint32) hostarch.Addr {
	return t.addr + hostarch.Addr(trapSize)*hostarch.Addr(trap)
}

// nextUsableTrap returns the next trap slot that fits entirely within one
// page. Trap slots that cross page boundaries are skipped.
func (t *trapTable) nextUsableTrap() (uint32, bool) {
	for trap := t.nextTrap; trap < trapNR; trap++ {
		addr := t.trapAddr(trap)
		end, ok := addr.AddLength(trapSize - 1)
		if !ok {
			return 0, false
		}
		if addr.RoundDown() == end.RoundDown() {
			return trap, true
		}
	}
	return 0, false
}

// reserveTrap selects the next usable slot and advances the in-memory
// allocation cursor. It does not update the persistent table header.
func (t *trapTable) reserveTrap() (trap uint32, addr hostarch.Addr, ok bool) {
	trap, ok = t.nextUsableTrap()
	if !ok {
		return 0, 0, false
	}

	addr = t.trapAddr(trap)
	t.nextTrap = trap + 1
	return trap, addr, true
}

// reachableFrom reports whether the next usable trap slot in t can be reached
// by an AArch64 B instruction at src.
func (t *trapTable) reachableFrom(src uintptr) bool {
	trap, ok := t.nextUsableTrap()
	if !ok {
		return false
	}
	_, ok = encodeBranch(src, uintptr(t.trapAddr(trap)))
	return ok
}

// recoverTrapTablesLocked reconstructs the runtime trap-table cache from
// [usertrap] VMAs whose starts lie in search.
//
// Invalid or unrelated mappings with the same VMA name are ignored. A
// non-zero VMA offset is never accepted as one of our trap tables.
//
// Preconditions: s.mu must be locked.
func (s *State) recoverTrapTablesLocked(ctx context.Context, mm memoryManager, search hostarch.AddrRange) error {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return fmt.Errorf("no task found")
	}

	for search.Start < search.End {
		addr, off, err := mm.FindVMAByName(search, tableVMAName)
		if err != nil {
			return nil
		}

		next, ok := addr.AddLength(uint64(hostarch.PageSize))
		if !ok || next <= addr {
			return fmt.Errorf("ARM64 usertrap VMA at %x overflows address space", addr)
		}

		// FindVMAByName searches VMA start addresses. Advance by one page from
		// this start before validating it; this guarantees progress without
		// assuming that an arbitrary same-name VMA has our expected size.
		search.Start = next

		if off != 0 {
			continue
		}

		var hdr header
		if _, err := hdr.CopyIn(task.OwnCopyContext(usermem.IOOpts{}), addr); err != nil {
			continue
		}
		if !hdr.valid() {
			continue
		}

		duplicate := false
		for i := range s.tables {
			if s.tables[i].addr == addr {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}

		s.tables = append(s.tables, trapTable{
			addr:     addr,
			nextTrap: hdr.nextTrap,
		})
	}
	return nil
}

// findReachableTableLocked returns a cached trap table whose next free slot is
// reachable from src.
//
// Preconditions: s.mu must be locked.
func (s *State) findReachableTableLocked(src uintptr) *trapTable {
	for i := range s.tables {
		if s.tables[i].reachableFrom(src) {
			return &s.tables[i]
		}
	}
	return nil
}

// getTrapTableLocked returns a trap table with a usable slot reachable from
// src. Existing tables are preferred; inherited/restored tables are recovered
// before a new VMA is created.
//
// If no candidate address can be mapped after a bounded number of collisions,
// (nil, nil) is returned so the caller can leave the original SVC untouched.
//
// Preconditions: s.mu must be locked.
func (s *State) getTrapTableLocked(ctx context.Context, mm memoryManager, src uintptr) (*trapTable, error) {
	if table := s.findReachableTableLocked(src); table != nil {
		return table, nil
	}

	start, end, ok := branchTableRange(src, uintptr(trapTableMappingSize()))
	if !ok {
		return nil, nil
	}

	search := hostarch.AddrRange{
		Start: hostarch.Addr(start),
		End:   hostarch.Addr(end),
	}
	if err := s.recoverTrapTablesLocked(ctx, mm, search); err != nil {
		return nil, err
	}
	if table := s.findReachableTableLocked(src); table != nil {
		return table, nil
	}

	pages := uint64((end - start) / hostarch.PageSize)
	attempts := pages
	if attempts > maxTrapTableMappingAttempts {
		attempts = maxTrapTableMappingAttempts
	}

	for attempt := uint64(0); attempt < attempts; attempt++ {
		candidate, ok := branchTableCandidate(start, end, attempt)
		if !ok {
			break
		}

		table, err := s.mapTrapTableLocked(ctx, mm, hostarch.Addr(candidate))
		if err == nil {
			// branchTableRange() constrains the entire table, but retain
			// this check as the final executable-branch invariant.
			if !table.reachableFrom(src) {
				badAddr := table.addr

				// mapTrapTableLocked appended this table as the final cache
				// entry. Remove it before unmapping the VMA.
				s.tables = s.tables[:len(s.tables)-1]

				if unmapErr := mm.MUnmap(ctx, badAddr, trapTableMappingSize()); unmapErr != nil {
					ctx.Warningf(
						"Failed to unmap unreachable ARM64 usertrap table at %x: %v",
						badAddr, unmapErr)
				}
				return nil, fmt.Errorf(
					"new ARM64 usertrap table at %x is unreachable from %x",
					badAddr, src)
			}
			return table, nil
		}
		if linuxerr.Equals(linuxerr.EEXIST, err) {
			continue
		}
		return nil, err
	}

	return nil, nil
}

// mapTrapTableLocked attempts to create a trap table at an exact address.
//
// Preconditions: s.mu must be locked.
func (s *State) mapTrapTableLocked(ctx context.Context, mm memoryManager, addr hostarch.Addr) (*trapTable, error) {
	if addr%hostarch.PageSize != 0 {
		return nil, fmt.Errorf("unaligned ARM64 usertrap address %x", addr)
	}

	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return nil, fmt.Errorf("no task found")
	}

	if err := loadUsertrap(ctx, mm, addr); err != nil {
		return nil, err
	}

	hdr := header{
		magic:    arm64TableMagic,
		version:  arm64TableVersion,
		nextTrap: 1, // Slot zero contains this header.
	}
	if _, err := hdr.CopyOut(
		task.OwnCopyContext(usermem.IOOpts{IgnorePermissions: true}),
		addr,
	); err != nil {
		if unmapErr := mm.MUnmap(ctx, addr, trapTableMappingSize()); unmapErr != nil {
			ctx.Warningf("Failed to unmap ARM64 usertrap table at %x after header initialization failure: %v", addr, unmapErr)
		}
		return nil, err
	}

	s.tables = append(s.tables, trapTable{
		addr:     addr,
		nextTrap: hdr.nextTrap,
	})
	return &s.tables[len(s.tables)-1], nil
}

func (*State) PatchSyscall(ctx context.Context, ac *arch.Context64, mm memoryManager) (restart bool, err error) {
	task := kernel.TaskFromContext(ctx)
	if task == nil {
		return false, fmt.Errorf("no task found")
	}

	// updateSyscallRegs() normalizes ac.IP() to the instruction following the
	// syscall before PatchSyscall is called. AArch64 instructions are 4 bytes,
	// so the trapped SVC is immediately before ac.IP().
	if ac.IP() < arm64InstSize {
		return false, nil
	}
	patchAddr := ac.IP() - arm64InstSize
	if patchAddr%arm64InstSize != 0 {
		return false, nil
	}

	var code [arm64InstSize]byte
	if _, err := primitive.CopyUint8SliceIn(task, hostarch.Addr(patchAddr), code[:]); err != nil {
		return false, err
	}

	// Only patch the canonical Linux AArch64 syscall instruction, SVC #0.
	if !isSyscallInstruction(binary.LittleEndian.Uint32(code[:])) {
		return false, nil
	}

	ctx.Debugf("Found ARM64 syscall instruction at ip %x: sysno %d", patchAddr, ac.SyscallNo())

	// Trap allocation and instruction replacement are added separately.
	// Leave the original SVC untouched for now.
	return false, nil
}

// HandleFault handles a fault on a patched syscall instruction.
func (*State) HandleFault(ctx context.Context, ac *arch.Context64, mm memoryManager) error {
	return nil
}

// PreFork prevents trap-table allocation or patching from racing with fork.
func (s *State) PreFork() {
	s.mu.RLock()
}

// PostFork releases the fork synchronization lock.
func (s *State) PostFork() {
	s.mu.RUnlock()
}
