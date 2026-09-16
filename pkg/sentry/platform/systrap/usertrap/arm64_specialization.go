// Copyright 2026 The gVisor Authors.
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

package usertrap

import (
	"encoding/binary"
	"fmt"
)

const (
	arm64SubX8ImmBase = uint32(0xd1000108)
	arm64AddX8ImmBase = uint32(0x91000108)
	arm64CBNZX8Base   = uint32(0xb5000008)

	arm64SpecializationInstructions = 2
	arm64SpecializationSize         = arm64SpecializationInstructions * arm64InstSize
)

func encodeX8Immediate(base uint32, imm uint64) (uint32, error) {
	if imm > 0xfff {
		return 0, fmt.Errorf("immediate %#x does not fit in imm12", imm)
	}
	return base | uint32(imm)<<10, nil
}

// encodeSubX8Immediate encodes:
//
//	sub x8, x8, #imm
//
// for an unshifted 12-bit immediate. SUB without the S suffix does not modify
// NZCV.
func encodeSubX8Immediate(imm uint64) (uint32, error) {
	return encodeX8Immediate(arm64SubX8ImmBase, imm)
}

// encodeAddX8Immediate encodes:
//
//	add x8, x8, #imm
//
// for an unshifted 12-bit immediate. This is used by the mismatch path to
// reconstruct the original syscall number before falling back to SVC.
func encodeAddX8Immediate(imm uint64) (uint32, error) {
	return encodeX8Immediate(arm64AddX8ImmBase, imm)
}

// encodeCBNZX8 encodes a CBNZ x8 from src to dst.
//
// AArch64 CBNZ uses a signed 19-bit immediate scaled by four, giving a branch
// range of [-1 MiB, 1 MiB - 4].
func encodeCBNZX8(src, dst uintptr) (uint32, error) {
	if src%arm64InstSize != 0 || dst%arm64InstSize != 0 {
		return 0, fmt.Errorf("unaligned CBNZ: src=%#x dst=%#x", src, dst)
	}

	var delta int64
	if dst >= src {
		d := dst - src
		if d > uintptr((1<<20)-arm64InstSize) {
			return 0, fmt.Errorf("CBNZ target out of range: src=%#x dst=%#x", src, dst)
		}
		delta = int64(d)
	} else {
		d := src - dst
		if d > uintptr(1<<20) {
			return 0, fmt.Errorf("CBNZ target out of range: src=%#x dst=%#x", src, dst)
		}
		delta = -int64(d)
	}

	imm19 := uint32(delta>>2) & 0x7ffff
	return arm64CBNZX8Base | imm19<<5, nil
}

// buildSyscallNumberCheck emits:
//
//	sub  x8, x8, #sysno
//	cbnz x8, mismatch
//
// Neither instruction modifies NZCV.
//
// On the fallthrough path x8 is zero, giving the trampoline a scratch register.
// On the mismatch path, x8 contains original_x8-sysno. The mismatch stub must
// add sysno back to x8 before executing the original SVC instruction.
//
// This helper does not publish a trap or implement the mismatch path.
func buildSyscallNumberCheck(addr, mismatch uintptr, sysno uint64) ([]byte, error) {
	sub, err := encodeSubX8Immediate(sysno)
	if err != nil {
		return nil, err
	}

	cbnz, err := encodeCBNZX8(addr+arm64InstSize, mismatch)
	if err != nil {
		return nil, err
	}

	code := make([]byte, arm64SpecializationSize)
	binary.LittleEndian.PutUint32(code[0:4], sub)
	binary.LittleEndian.PutUint32(code[4:8], cbnz)
	return code, nil
}
