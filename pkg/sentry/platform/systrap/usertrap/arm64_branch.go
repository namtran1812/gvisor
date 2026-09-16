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

import "gvisor.dev/gvisor/pkg/hostarch"

const (
	// AArch64 B encodes a signed 26-bit immediate containing the branch
	// displacement in units of 4-byte instructions.
	arm64BranchOpcode uint32 = 0x14000000
	arm64BranchMask   uint32 = 0x03ffffff
	arm64BranchRange         = 1 << 27 // +/-128 MiB.
	arm64InstSize            = 4
	arm64Svc0         uint32 = 0xd4000001
)

// encodeBranch encodes an AArch64 unconditional immediate branch from src to
// dst. Both addresses must be instruction-aligned and dst must be reachable
// using B's signed imm26 displacement.
func encodeBranch(src, dst uintptr) (uint32, bool) {
	if src%arm64InstSize != 0 || dst%arm64InstSize != 0 {
		return 0, false
	}

	var imm26 int64
	if dst >= src {
		delta := dst - src
		if delta >= arm64BranchRange {
			return 0, false
		}
		imm26 = int64(delta / arm64InstSize)
	} else {
		delta := src - dst
		if delta > arm64BranchRange {
			return 0, false
		}
		imm26 = -int64(delta / arm64InstSize)
	}

	return arm64BranchOpcode | uint32(imm26)&arm64BranchMask, true
}

// isSyscallInstruction reports whether inst is the canonical Linux AArch64
// syscall instruction, SVC #0.
func isSyscallInstruction(inst uint32) bool {
	return inst == arm64Svc0
}

// branchTableRange returns the range of page-aligned trap-table base addresses
// for which every instruction-aligned target in a table of tableSize bytes is
// reachable by an AArch64 B instruction at src.
//
// tableSize must be a non-zero multiple of the AArch64 instruction size. The
// returned end is exclusive.
func branchTableRange(src, tableSize uintptr) (start, end uintptr, ok bool) {
	if src%arm64InstSize != 0 ||
		tableSize < arm64InstSize ||
		tableSize%arm64InstSize != 0 {
		return 0, 0, false
	}

	// AArch64 B has a signed 26-bit immediate scaled by 4, so the
	// reachable byte displacement is [-128 MiB, +128 MiB - 4].
	var low uintptr
	if src >= arm64BranchRange {
		low = src - arm64BranchRange
	}

	max := ^uintptr(0)
	maxAligned := max &^ uintptr(arm64InstSize-1)
	maxForward := uintptr(arm64BranchRange - arm64InstSize)

	var maxDst uintptr
	if src > maxAligned-maxForward {
		maxDst = maxAligned
	} else {
		maxDst = src + maxForward
	}

	// The final instruction-sized unit in the table must remain reachable.
	lastOffset := tableSize - arm64InstSize
	if lastOffset > maxDst {
		return 0, 0, false
	}
	high := maxDst - lastOffset

	pageMask := uintptr(hostarch.PageSize - 1)
	if low > max-pageMask {
		return 0, 0, false
	}
	start = (low + pageMask) &^ pageMask
	high &= ^pageMask

	if start > high || high > max-uintptr(hostarch.PageSize) {
		return 0, 0, false
	}
	return start, high + uintptr(hostarch.PageSize), true
}

// branchTableCandidate returns a page-aligned candidate trap-table address
// within [start, end). Candidates are spread deterministically across the
// range so a bounded number of probes does not cluster inside one large VMA.
//
// attempt 0 selects the midpoint. Later attempts use an odd stride over the
// page indices; because the stride is derived to be coprime with the page
// count, all pages are visited exactly once if probing is allowed to continue.
//
// The caller must still verify that the candidate VMA is free.
func branchTableCandidate(start, end uintptr, attempt uint64) (uintptr, bool) {
	if start%hostarch.PageSize != 0 ||
		end%hostarch.PageSize != 0 ||
		start >= end {
		return 0, false
	}

	pages := uint64((end - start) / hostarch.PageSize)
	if pages == 0 || attempt >= pages {
		return 0, false
	}

	mid := pages / 2
	if attempt == 0 {
		return start + uintptr(mid)*hostarch.PageSize, true
	}

	// Choose a stride near half the range, then increment it until it is
	// coprime with pages. This gives broad spatial coverage while ensuring
	// that every page index is eventually visited exactly once.
	stride := pages/2 + 1
	for gcd64(stride, pages) != 1 {
		stride++
		if stride == pages {
			stride = 1
		}
	}

	// The caller bounds attempts to a small number within AArch64's
	// approximately 256 MiB branch window, so this multiplication cannot
	// overflow uint64 in practice.
	page := (mid + attempt*stride) % pages

	return start + uintptr(page)*hostarch.PageSize, true
}

func gcd64(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
