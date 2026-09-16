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

#ifndef THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_ARM64_H_
#define THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_ARM64_H_

// Linux arm64's user_regs_struct contains x0-x30 consecutively, followed by
// sp, pc, and pstate. All fields are 64 bits.
#define offsetof_thread_context_ptregs_x(n) \
  (offsetof_thread_context_ptregs + ((n) * 8))

#define offsetof_thread_context_ptregs_sp \
  (offsetof_thread_context_ptregs + (31 * 8))
#define offsetof_thread_context_ptregs_pc \
  (offsetof_thread_context_ptregs + (32 * 8))
#define offsetof_thread_context_ptregs_pstate \
  (offsetof_thread_context_ptregs + (33 * 8))

#endif  // THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_SYSMSG_OFFSETS_ARM64_H_
