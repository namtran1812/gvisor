// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build arm64

package usertrap

import (
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestEncodeBranch(t *testing.T) {
	tests := []struct {
		name string
		src  uintptr
		dst  uintptr
		want uint32
		ok   bool
	}{
		{
			name: "next instruction",
			src:  0x1000,
			dst:  0x1004,
			want: 0x14000001,
			ok:   true,
		},
		{
			name: "previous instruction",
			src:  0x1004,
			dst:  0x1000,
			want: 0x17ffffff,
			ok:   true,
		},
		{
			name: "same address",
			src:  0x1000,
			dst:  0x1000,
			want: 0x14000000,
			ok:   true,
		},
		{
			name: "largest forward branch",
			src:  0,
			dst:  arm64BranchRange - arm64InstSize,
			want: 0x15ffffff,
			ok:   true,
		},
		{
			name: "forward out of range",
			src:  0,
			dst:  arm64BranchRange,
			ok:   false,
		},
		{
			name: "largest backward branch",
			src:  arm64BranchRange,
			dst:  0,
			want: 0x16000000,
			ok:   true,
		},
		{
			name: "backward out of range",
			src:  arm64BranchRange + arm64InstSize,
			dst:  0,
			ok:   false,
		},
		{
			name: "unaligned source",
			src:  0x1001,
			dst:  0x2000,
			ok:   false,
		},
		{
			name: "unaligned destination",
			src:  0x1000,
			dst:  0x2002,
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := encodeBranch(tc.src, tc.dst)
			if ok != tc.ok {
				t.Fatalf("encodeBranch(%#x, %#x) ok=%v, want %v",
					tc.src, tc.dst, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("encodeBranch(%#x, %#x)=%#08x, want %#08x",
					tc.src, tc.dst, got, tc.want)
			}
		})
	}
}

func TestIsSyscallInstruction(t *testing.T) {
	tests := []struct {
		name string
		inst uint32
		want bool
	}{
		{
			name: "svc zero",
			inst: arm64Svc0,
			want: true,
		},
		{
			name: "svc one",
			inst: 0xd4000021,
			want: false,
		},
		{
			name: "branch",
			inst: arm64BranchOpcode,
			want: false,
		},
		{
			name: "zero",
			inst: 0,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSyscallInstruction(tc.inst); got != tc.want {
				t.Fatalf("isSyscallInstruction(%#08x)=%v, want %v",
					tc.inst, got, tc.want)
			}
		})
	}
}

func TestBranchTableRange(t *testing.T) {
	const tableSize = uintptr(0x5000)

	tests := []struct {
		name      string
		src       uintptr
		tableSize uintptr
		wantOK    bool
	}{
		{
			name:      "normal address",
			src:       0x40000000,
			tableSize: tableSize,
			wantOK:    true,
		},
		{
			name:      "near zero",
			src:       0x1000,
			tableSize: tableSize,
			wantOK:    true,
		},
		{
			name:      "unaligned source",
			src:       0x40000002,
			tableSize: tableSize,
			wantOK:    false,
		},
		{
			name:      "zero table",
			src:       0x40000000,
			tableSize: 0,
			wantOK:    false,
		},
		{
			name:      "table smaller than instruction",
			src:       0x40000000,
			tableSize: arm64InstSize - 1,
			wantOK:    false,
		},
		{
			name:      "table not instruction aligned",
			src:       0x40000000,
			tableSize: arm64InstSize + 1,
			wantOK:    false,
		},
		{
			name:      "table larger than branch window",
			src:       0x40000000,
			tableSize: uintptr(2*arm64BranchRange + arm64InstSize),
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			start, end, ok := branchTableRange(tc.src, tc.tableSize)
			if ok != tc.wantOK {
				t.Fatalf(
					"branchTableRange(%#x, %#x) ok=%t, want %t",
					tc.src, tc.tableSize, ok, tc.wantOK,
				)
			}
			if !ok {
				return
			}

			if start%hostarch.PageSize != 0 {
				t.Fatalf("start %#x is not page-aligned", start)
			}
			if end%hostarch.PageSize != 0 {
				t.Fatalf("end %#x is not page-aligned", end)
			}
			if start >= end {
				t.Fatalf("invalid range [%#x, %#x)", start, end)
			}

			firstLastInst := start + tc.tableSize - arm64InstSize
			if _, reachable := encodeBranch(tc.src, start); !reachable {
				t.Fatalf("first table base %#x is unreachable from %#x",
					start, tc.src)
			}
			if _, reachable := encodeBranch(tc.src, firstLastInst); !reachable {
				t.Fatalf("first table final instruction %#x is unreachable from %#x",
					firstLastInst, tc.src)
			}

			lastBase := end - hostarch.PageSize
			lastInst := lastBase + tc.tableSize - arm64InstSize
			if _, reachable := encodeBranch(tc.src, lastBase); !reachable {
				t.Fatalf("last table base %#x is unreachable from %#x",
					lastBase, tc.src)
			}
			if _, reachable := encodeBranch(tc.src, lastInst); !reachable {
				t.Fatalf("last table final instruction %#x is unreachable from %#x",
					lastInst, tc.src)
			}
		})
	}
}

func TestBranchTableCandidate(t *testing.T) {
	const (
		start = uintptr(0x10000)
		end   = uintptr(0x18000)
	)

	pages := uint64((end - start) / hostarch.PageSize)
	seen := make(map[uintptr]bool)

	for attempt := uint64(0); attempt < pages; attempt++ {
		addr, ok := branchTableCandidate(start, end, attempt)
		if !ok {
			t.Fatalf("branchTableCandidate(%#x, %#x, %d) failed",
				start, end, attempt)
		}
		if addr < start || addr >= end {
			t.Fatalf("candidate %#x outside [%#x, %#x)", addr, start, end)
		}
		if addr%hostarch.PageSize != 0 {
			t.Fatalf("candidate %#x is not page-aligned", addr)
		}
		if seen[addr] {
			t.Fatalf("candidate %#x returned more than once", addr)
		}
		seen[addr] = true
	}

	if uint64(len(seen)) != pages {
		t.Fatalf("visited %d candidates, want %d", len(seen), pages)
	}
}

func TestBranchTableCandidateSpreadsEarlyProbes(t *testing.T) {
	const (
		start = uintptr(0x10000000)
		pages = uint64(65536)
		end   = start + uintptr(pages)*hostarch.PageSize
	)

	first, ok := branchTableCandidate(start, end, 0)
	if !ok {
		t.Fatal("first candidate failed")
	}
	second, ok := branchTableCandidate(start, end, 1)
	if !ok {
		t.Fatal("second candidate failed")
	}

	delta := first
	if second > first {
		delta = second - first
	} else {
		delta = first - second
	}

	// Early probes should not simply walk adjacent pages.
	if delta <= 16*hostarch.PageSize {
		t.Fatalf("first two candidates are too clustered: %#x and %#x",
			first, second)
	}
}

func TestBranchTableCandidateInvalidRange(t *testing.T) {
	tests := []struct {
		name       string
		start, end uintptr
	}{
		{
			name:  "empty",
			start: 0x10000,
			end:   0x10000,
		},
		{
			name:  "reversed",
			start: 0x18000,
			end:   0x10000,
		},
		{
			name:  "unaligned start",
			start: 0x10001,
			end:   0x18000,
		},
		{
			name:  "unaligned end",
			start: 0x10000,
			end:   0x18001,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if addr, ok := branchTableCandidate(tc.start, tc.end, 0); ok {
				t.Fatalf("branchTableCandidate(%#x, %#x, 0)=%#x, want failure",
					tc.start, tc.end, addr)
			}
		})
	}
}

func TestEncodeBranchAddressExtremes(t *testing.T) {
	max := ^uintptr(0)

	tests := []struct {
		name string
		src  uintptr
		dst  uintptr
		ok   bool
	}{
		{
			name: "high addresses forward",
			src:  (max &^ uintptr(arm64InstSize-1)) - uintptr(arm64BranchRange),
			dst:  (max &^ uintptr(arm64InstSize-1)) - uintptr(arm64BranchRange) + arm64InstSize,
			ok:   true,
		},
		{
			name: "high addresses backward",
			src:  max &^ uintptr(arm64InstSize-1),
			dst:  (max &^ uintptr(arm64InstSize-1)) - arm64InstSize,
			ok:   true,
		},
		{
			name: "maximum backward displacement",
			src:  uintptr(arm64BranchRange),
			dst:  0,
			ok:   true,
		},
		{
			name: "backward out of range",
			src:  uintptr(arm64BranchRange) + arm64InstSize,
			dst:  0,
			ok:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := encodeBranch(tc.src, tc.dst)
			if ok != tc.ok {
				t.Fatalf("encodeBranch(%#x, %#x) ok=%t, want %t",
					tc.src, tc.dst, ok, tc.ok)
			}
		})
	}
}

func TestNextUsableTrap(t *testing.T) {
	tests := []struct {
		name     string
		table    trapTable
		wantTrap uint32
		wantOK   bool
	}{
		{
			name: "first trap fits",
			table: trapTable{
				addr:     0x10000,
				nextTrap: 1,
			},
			wantTrap: 1,
			wantOK:   true,
		},
		{
			name: "skip page crossing trap",
			// 0x10000 + 51*80 = 0x10ff0, so slot 51 crosses
			// the page boundary. Slot 52 starts at 0x11040.
			table: trapTable{
				addr:     0x10000,
				nextTrap: 51,
			},
			wantTrap: 52,
			wantOK:   true,
		},
		{
			name: "full table",
			table: trapTable{
				addr:     0x10000,
				nextTrap: trapNR,
			},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.table.nextUsableTrap()
			if ok != tc.wantOK {
				t.Fatalf("nextUsableTrap() ok=%t, want %t", ok, tc.wantOK)
			}
			if ok && got != tc.wantTrap {
				t.Fatalf("nextUsableTrap()=%d, want %d", got, tc.wantTrap)
			}
		})
	}
}

func TestTrapTableReachableFrom(t *testing.T) {
	const tableAddr = uintptr(0x40000000)

	tests := []struct {
		name  string
		table trapTable
		src   uintptr
		want  bool
	}{
		{
			name: "reachable",
			table: trapTable{
				addr:     hostarch.Addr(tableAddr),
				nextTrap: 1,
			},
			src:  tableAddr,
			want: true,
		},
		{
			name: "reachable after skipping crossing slot",
			table: trapTable{
				addr:     hostarch.Addr(tableAddr),
				nextTrap: 51,
			},
			src:  tableAddr,
			want: true,
		},
		{
			name: "forward out of range",
			table: trapTable{
				addr:     hostarch.Addr(tableAddr + arm64BranchRange),
				nextTrap: 1,
			},
			src:  tableAddr,
			want: false,
		},
		{
			name: "full",
			table: trapTable{
				addr:     hostarch.Addr(tableAddr),
				nextTrap: trapNR,
			},
			src:  tableAddr,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.table.reachableFrom(tc.src); got != tc.want {
				t.Fatalf("reachableFrom(%#x)=%t, want %t",
					tc.src, got, tc.want)
			}
		})
	}
}

func TestBranchTableRangeAddressExtremes(t *testing.T) {
	const tableSize = uintptr(0x5000)

	// Put src close enough to uintptr's maximum that adding the maximum
	// forward branch displacement would overflow. branchTableRange must
	// saturate the reachable destination rather than wrapping around.
	maxAligned := ^uintptr(0) &^ uintptr(arm64InstSize-1)
	src := maxAligned - uintptr(hostarch.PageSize)

	start, end, ok := branchTableRange(src, tableSize)
	if !ok {
		t.Fatalf("branchTableRange(%#x, %#x) failed near uintptr maximum",
			src, tableSize)
	}
	if start%hostarch.PageSize != 0 || end%hostarch.PageSize != 0 {
		t.Fatalf("range [%#x, %#x) is not page-aligned", start, end)
	}
	if start >= end {
		t.Fatalf("invalid range [%#x, %#x)", start, end)
	}

	firstLastInst := start + tableSize - arm64InstSize
	if _, ok := encodeBranch(src, start); !ok {
		t.Fatalf("first table base %#x is unreachable from %#x", start, src)
	}
	if _, ok := encodeBranch(src, firstLastInst); !ok {
		t.Fatalf("first table final instruction %#x is unreachable from %#x",
			firstLastInst, src)
	}

	lastBase := end - hostarch.PageSize
	if lastBase > ^uintptr(0)-(tableSize-arm64InstSize) {
		t.Fatalf("last table at %#x overflows uintptr", lastBase)
	}
	lastInst := lastBase + tableSize - arm64InstSize
	if _, ok := encodeBranch(src, lastBase); !ok {
		t.Fatalf("last table base %#x is unreachable from %#x", lastBase, src)
	}
	if _, ok := encodeBranch(src, lastInst); !ok {
		t.Fatalf("last table final instruction %#x is unreachable from %#x",
			lastInst, src)
	}
}

func TestReserveTrap(t *testing.T) {
	tests := []struct {
		name         string
		table        trapTable
		wantTrap     uint32
		wantAddr     hostarch.Addr
		wantNextTrap uint32
		wantOK       bool
	}{
		{
			name: "reserve first slot",
			table: trapTable{
				addr:     0x10000,
				nextTrap: 1,
			},
			wantTrap:     1,
			wantAddr:     0x10000 + trapSize,
			wantNextTrap: 2,
			wantOK:       true,
		},
		{
			name: "skip crossing slot",
			table: trapTable{
				addr:     0x10000,
				nextTrap: 51,
			},
			wantTrap:     52,
			wantAddr:     0x11040,
			wantNextTrap: 53,
			wantOK:       true,
		},
		{
			name: "full table",
			table: trapTable{
				addr:     0x10000,
				nextTrap: trapNR,
			},
			wantNextTrap: trapNR,
			wantOK:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table := tc.table
			trap, addr, ok := table.reserveTrap()

			if ok != tc.wantOK {
				t.Fatalf("reserveTrap() ok=%t, want %t", ok, tc.wantOK)
			}
			if ok {
				if trap != tc.wantTrap {
					t.Fatalf("reserveTrap() trap=%d, want %d",
						trap, tc.wantTrap)
				}
				if addr != tc.wantAddr {
					t.Fatalf("reserveTrap() addr=%#x, want %#x",
						addr, tc.wantAddr)
				}
			}
			if table.nextTrap != tc.wantNextTrap {
				t.Fatalf("nextTrap=%d after reserveTrap(), want %d",
					table.nextTrap, tc.wantNextTrap)
			}
		})
	}
}

func TestEncodeSubX8Immediate(t *testing.T) {
	tests := []struct {
		name string
		imm  uint64
		want uint32
	}{
		{name: "zero", imm: 0, want: 0xd1000108},
		{name: "syscall63", imm: 63, want: 0xd100fd08},
		{name: "max", imm: 0xfff, want: 0xd13ffd08},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := encodeSubX8Immediate(test.imm)
			if err != nil {
				t.Fatalf("encodeSubX8Immediate(%d): %v", test.imm, err)
			}
			if got != test.want {
				t.Fatalf("encodeSubX8Immediate(%d) = %#08x, want %#08x", test.imm, got, test.want)
			}
		})
	}

	if _, err := encodeSubX8Immediate(0x1000); err == nil {
		t.Fatalf("encodeSubX8Immediate(0x1000) succeeded, want error")
	}
}

func TestEncodeAddX8Immediate(t *testing.T) {
	tests := []struct {
		name string
		imm  uint64
		want uint32
	}{
		{name: "zero", imm: 0, want: 0x91000108},
		{name: "syscall63", imm: 63, want: 0x9100fd08},
		{name: "max", imm: 0xfff, want: 0x913ffd08},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := encodeAddX8Immediate(test.imm)
			if err != nil {
				t.Fatalf("encodeAddX8Immediate(%d): %v", test.imm, err)
			}
			if got != test.want {
				t.Fatalf("encodeAddX8Immediate(%d) = %#08x, want %#08x", test.imm, got, test.want)
			}
		})
	}

	if _, err := encodeAddX8Immediate(0x1000); err == nil {
		t.Fatalf("encodeAddX8Immediate(0x1000) succeeded, want error")
	}
}

func TestEncodeCBNZX8(t *testing.T) {
	tests := []struct {
		name string
		src  uintptr
		dst  uintptr
		want uint32
	}{
		{
			name: "assemblerForward",
			src:  0x18,
			dst:  0x20,
			want: 0xb5000048,
		},
		{
			name: "assemblerBackward",
			src:  0x20,
			dst:  0x0,
			want: 0xb5ffff08,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := encodeCBNZX8(test.src, test.dst)
			if err != nil {
				t.Fatalf("encodeCBNZX8(%#x, %#x): %v", test.src, test.dst, err)
			}
			if got != test.want {
				t.Fatalf("encodeCBNZX8(%#x, %#x) = %#08x, want %#08x",
					test.src, test.dst, got, test.want)
			}
		})
	}

	const src = uintptr(0x100000)

	if _, err := encodeCBNZX8(src, src+(1<<20)-arm64InstSize); err != nil {
		t.Fatalf("maximum forward CBNZ failed: %v", err)
	}
	if _, err := encodeCBNZX8(src, src-(1<<20)); err != nil {
		t.Fatalf("maximum backward CBNZ failed: %v", err)
	}
	if _, err := encodeCBNZX8(src, src+(1<<20)); err == nil {
		t.Fatalf("out-of-range forward CBNZ succeeded")
	}
	if _, err := encodeCBNZX8(src, src-(1<<20)-arm64InstSize); err == nil {
		t.Fatalf("out-of-range backward CBNZ succeeded")
	}
	if _, err := encodeCBNZX8(src, src+2); err == nil {
		t.Fatalf("unaligned CBNZ succeeded")
	}
}

func TestBuildSyscallNumberCheck(t *testing.T) {
	const (
		addr     = uintptr(0x10000)
		mismatch = uintptr(0x10040)
		sysno    = uint64(63)
	)

	code, err := buildSyscallNumberCheck(addr, mismatch, sysno)
	if err != nil {
		t.Fatalf("buildSyscallNumberCheck: %v", err)
	}
	if len(code) != arm64SpecializationSize {
		t.Fatalf("len(code) = %d, want %d", len(code), arm64SpecializationSize)
	}

	if got := binary.LittleEndian.Uint32(code[:4]); got != 0xd100fd08 {
		t.Fatalf("sub = %#08x, want %#08x", got, uint32(0xd100fd08))
	}

	wantBranch, err := encodeCBNZX8(addr+arm64InstSize, mismatch)
	if err != nil {
		t.Fatalf("encodeCBNZX8: %v", err)
	}
	if got := binary.LittleEndian.Uint32(code[4:]); got != wantBranch {
		t.Fatalf("cbnz = %#08x, want %#08x", got, wantBranch)
	}
}
