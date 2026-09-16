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

import "fmt"

const (
	arm64MRSTPIDREL0 = uint32(0xd53bd048)
	arm64NEGX8       = uint32(0xcb0803e8)
	arm64SWPAX8      = uint32(0xf8a88108)

	arm64CBZX8Base  = uint32(0xb4000008)
	arm64CBNZX8Base = uint32(0xb5000008)
)

func encodeCompareBranchX8(src, dst uintptr, base uint32) (uint32, error) {
	if src%arm64InstSize != 0 || dst%arm64InstSize != 0 {
		return 0, fmt.Errorf("unaligned compare-and-branch: src=%#x dst=%#x", src, dst)
	}

	var delta int64
	if dst >= src {
		d := dst - src
		if d > uintptr((1<<20)-arm64InstSize) {
			return 0, fmt.Errorf("compare-and-branch target out of range: src=%#x dst=%#x", src, dst)
		}
		delta = int64(d)
	} else {
		d := src - dst
		if d > uintptr(1<<20) {
			return 0, fmt.Errorf("compare-and-branch target out of range: src=%#x dst=%#x", src, dst)
		}
		delta = -int64(d)
	}

	imm19 := uint32(delta>>2) & 0x7ffff
	return base | imm19<<5, nil
}

func encodeCBZX8(src, dst uintptr) (uint32, error) {
	return encodeCompareBranchX8(src, dst, arm64CBZX8Base)
}

func encodeCBNZX8(src, dst uintptr) (uint32, error) {
	return encodeCompareBranchX8(src, dst, arm64CBNZX8Base)
}
