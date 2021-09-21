/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "runtime/Native/Intrinsics.h"
#include "runtime/Native/OS/Linux/SystemCall.cpp"

inline static addr_t CurrentPC(X86State &state) {
  return state.gpr.rip.aword;
}

extern "C" {

// Debug registers.
uint64_t DR0;
uint64_t DR1;
uint64_t DR2;
uint64_t DR3;
uint64_t DR4;
uint64_t DR5;
uint64_t DR6;
uint64_t DR7;

// Control regs.
CR0Reg gCR0;
CR1Reg gCR1;
CR2Reg gCR2;
CR3Reg gCR3;
CR4Reg gCR4;
CR8Reg gCR8;

}  // extern C

#define COMMON_X86_METHODS \
  addr_t GetPC(const State *state) const { \
    return state->gpr.rip.aword; \
  } \
  void SetPC(State *state, addr_t new_pc) const { \
    state->gpr.rip.aword = new_pc; \
  } \
  void SetSP(State *state, addr_t new_sp) const { \
    state->gpr.rsp.aword = new_sp; \
  } \
  addr_t GetSystemCallNum(Memory *, State *state) const { \
    return state->gpr.rax.aword; \
  } \
  addr_t GetInterruptNum(Memory *, State *state) const { \
    return state->hyper_call_vector; \
  } \


// 32-bit `int 0x80` system call ABI.
class X86Int0x80SystemCall: public SystemCallABI<X86Int0x80SystemCall> {
public:
  COMMON_X86_METHODS

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const {
    return ret_addr;
  }

  Memory *DoSetReturn(Memory *memory, State *state, addr_t ret_val) const {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const {
    return num_args <= 6;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#283
  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
    case 0:
      return state->gpr.rbx.aword;
    case 1:
      return state->gpr.rcx.aword;
    case 2:
      return state->gpr.rdx.aword;
    case 3:
      return state->gpr.rsi.aword;
    case 4:
      return state->gpr.rdi.aword;
    case 5:
      return state->gpr.rbp.aword;
    default:
      return 0;
    }
  }
};

// 32-bit `sysenter` ABI.
class X86SysEnter32SystemCall: public SystemCallABI<X86SysEnter32SystemCall> {
public:
  COMMON_X86_METHODS

  // Find the return address of this system call.
  addr_t GetReturnAddress(Memory *memory, State *, addr_t ret_addr) const {
    addr_t addr = ret_addr;
    for (addr_t i = 0; i < 15; ++i) {
      uint8_t b0 = 0;

      if (TryReadMemory(memory, addr + i, &b0)) {
        if (0x90 == b0) {  // NOP.
          continue;
        } else if (0xcd == b0) {  // First byte of `int N` instruction.
          return addr + i + 2;
        } else {
          return addr + i;
        }
      }
    }
    return addr;
  }

  bool CanReadArgs(Memory *memory, State *state, int num_args) const {
    if (num_args == 6) {
      addr_t arg6_addr = state->gpr.rbp.aword;
      return CanReadMemory(memory, arg6_addr, sizeof(addr_t));
    } else {
      return num_args < 6;
    }
  }

  Memory *DoSetReturn(Memory *memory, State *state, addr_t ret_val) const {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64_compat.S.html#38
  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
    case 0:
      return state->gpr.rbx.aword;
    case 1:
      return state->gpr.rcx.aword;
    case 2:
      return state->gpr.rdx.aword;
    case 3:
      return state->gpr.rsi.aword;
    case 4:
      return state->gpr.rdi.aword;
    case 5:
      return ReadMemory<addr_t>(memory, state->gpr.rbp.aword);
    default:
      return 0;
    }
  }
};

// 64-bit `syscall` system call ABI.
class Amd64SyscallSystemCall: public SystemCallABI<Amd64SyscallSystemCall> {
public:
  COMMON_X86_METHODS

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const {
    return ret_addr;
  }

  Memory *DoSetReturn(Memory *memory, State *state, addr_t ret_val) const {
    state->gpr.rax.aword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const {
    return num_args <= 6;
  }

  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64.S.html#106
  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
    case 0:
      return state->gpr.rdi.aword;
    case 1:
      return state->gpr.rsi.aword;
    case 2:
      return state->gpr.rdx.aword;
    case 3:
      return state->gpr.r10.aword;
    case 4:
      return state->gpr.r8.aword;
    case 5:
      return state->gpr.r9.aword;
    default:
      return 0;
    }
  }
};

// 64-bit libc/regular function call ABI.

class HandleLibcIntercept: public SystemCallABI<HandleLibcIntercept> {
  // TODO(sai) support variable length arguments
public:
  COMMON_X86_METHODS

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const {
    return ret_addr;
  }
  Memory *DoSetReturn(Memory *memory, State *state, addr_t ret_val) const {
    state->gpr.rax.aword = ret_val;
    return memory;
  }
  bool CanReadArgs(Memory *, State *, int num_args) const {
    bool can_read = num_args <= 6;
    if (!can_read)
      puts("DO NOT YET SUPPORT VAR ARGS");
    return can_read;
  }
  // See https://code.woboq.org/linux/linux/arch/x86/entry/entry_64.S.html#106
  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
    case 0:
      return state->gpr.rdi.aword;
    case 1:
      return state->gpr.rsi.aword;
    case 2:
      return state->gpr.rdx.aword;
    case 3:
      return state->gpr.rcx.aword;
    case 4:
      return state->gpr.r8.aword;
    case 5:
      return state->gpr.r9.aword;
    default:
      return 0;
    }
  }
};

extern "C" {

Memory *__remill_async_hyper_call(State &state, addr_t ret_addr,
    Memory *memory) {
  auto &task = reinterpret_cast<linux_task &>(state);
  switch (state.hyper_call) {
#if 32 == ADDRESS_SIZE_BITS
    case AsyncHyperCall::kX86SysEnter: {
      X86SysEnter32SystemCall syscall;
      auto user_stack = state.gpr.rsp.aword;
      memory = X86SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
        state.gpr.rip.aword = ret_addr;
        state.gpr.rsp.aword = user_stack;
        task.last_pc = ret_addr;
        task.location = kTaskStoppedAfterHyperCall;
        task.status = kTaskStatusRunnable;
        task.continuation = __kleemill_get_lifted_function(memory, task.last_pc);
      } else {
        task.last_pc = ret_addr;
        task.location = kTaskStoppedBeforeHyperCall;
        task.status = kTaskStatusResumable;
        task.continuation = __remill_async_hyper_call;
      }
      break;
    }

    case AsyncHyperCall::kX86IntN:
    if (0x80 == state.hyper_call_vector) {
      X86Int0x80SystemCall syscall;
      memory = X86SystemCall(memory, &state, syscall);
      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
        state.gpr.rip.aword = ret_addr;
        task.last_pc = ret_addr;
        task.location = kTaskStoppedAfterHyperCall;
        task.status = kTaskStatusRunnable;
        task.continuation = __kleemill_get_lifted_function(memory, task.last_pc);
      } else {
        task.last_pc = ret_addr;
        task.location = kTaskStoppedBeforeHyperCall;
        task.status = kTaskStatusResumable;
        task.continuation = __remill_async_hyper_call;
      }
    }

    break;
#endif

#if 64 == ADDRESS_SIZE_BITS
    case AsyncHyperCall::kX86SysCall: {
      Amd64SyscallSystemCall syscall;
      memory = AMD64SystemCall(memory, &state, syscall);
      if(task.status == kTaskStatusExited) {
          break;
      }

      if (syscall.Completed()) {
        ret_addr = syscall.GetReturnAddress(memory, &state, ret_addr);
        state.gpr.rip.aword = ret_addr;
        state.gpr.rcx.aword = ret_addr;
        task.last_pc = ret_addr;
        task.location = kTaskStoppedAfterHyperCall;
        task.status = kTaskStatusRunnable;
        task.continuation = __kleemill_get_lifted_function(memory, task.last_pc);
      } else {
        task.last_pc = ret_addr;
        task.location = kTaskStoppedBeforeHyperCall;
        task.status = kTaskStatusResumable;
        task.continuation = __remill_async_hyper_call;
      }
      break;
    }
    case AsyncHyperCall::kX86IntN: {
      HandleLibcIntercept intercept;
      memory = HandleLibcInterceptCall(memory, &state, intercept);
      ret_addr = intercept.GetReturnAddress(memory, &state, ret_addr);

//      printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
//          //__remill_read_memory_8(memory, ret_addr),
//          __remill_read_memory_8(memory, ret_addr+1),
//          __remill_read_memory_8(memory, ret_addr + 2),
//          __remill_read_memory_8(memory, ret_addr+3),
//          __remill_read_memory_8(memory,  ret_addr+4),
//          __remill_read_memory_8(memory, ret_addr+5),
//          __remill_read_memory_8(memory,ret_addr + 6),
//          __remill_read_memory_8(memory,ret_addr + 7),
//          __remill_read_memory_8(memory, ret_addr +8),
//          __remill_read_memory_8(memory, ret_addr+9),
//          __remill_read_memory_8(memory, ret_addr + 10),
//          __remill_read_memory_8(memory, ret_addr+11),
//          __remill_read_memory_8(memory,  ret_addr+12),
//          __remill_read_memory_8(memory, ret_addr+13),
//          __remill_read_memory_8(memory,ret_addr + 14),
//          __remill_read_memory_8(memory,ret_addr + 15),
//          __remill_read_memory_8(memory, ret_addr +16),
//          __remill_read_memory_8(memory, ret_addr+17),
//          __remill_read_memory_8(memory, ret_addr + 18),
//          __remill_read_memory_8(memory, ret_addr+19),
//          __remill_read_memory_8(memory,  ret_addr+20),
//          __remill_read_memory_8(memory, ret_addr+21),
//          __remill_read_memory_8(memory,ret_addr + 22),
//          __remill_read_memory_8(memory,ret_addr + 23)
//      );
      //exit(0);
      if (intercept.Completed()) {
        state.gpr.rip.aword = ret_addr;
        task.last_pc = ret_addr;

      // If the intercept didn't complete, then skip over the `ret` instruction.
      } else {
        intercept.SetReturn(memory, &state, state.gpr.rax.aword);
        state.gpr.rip.aword = ret_addr + 1;
        task.last_pc = ret_addr;
      }
      task.location = kTaskStoppedAtCallTarget;
      task.status = kTaskStatusRunnable;
      task.continuation = __kleemill_get_lifted_function(memory, task.last_pc);
      break;
    }

#endif
  default:
    puts("hit default case");
    task.last_pc = ret_addr;
    task.location = kTaskStoppedBeforeUnhandledHyperCall;
    task.status = kTaskStatusError;
    task.continuation = __kleemill_at_unhandled_hypercall;
    break;
  }

  if (task.status == kTaskStatusRunnable) {
    return task.continuation(task.state, task.last_pc, memory);

    // Error, or paused, bubble up the call stack to get us back to
  } else {
    return memory;
  }
}

Memory *__remill_sync_hyper_call(X86State &state, Memory *mem,
    SyncHyperCall::Name call) {

  auto &task = reinterpret_cast<linux_task &>(state);
  task.time_stamp_counter += 500;

  switch (call) {
  case SyncHyperCall::kInvalid:
    task.location = kTaskStoppedAtError;
    task.last_pc = CurrentPC(state);
    break;

  case SyncHyperCall::kX86SetSegmentES:
    STRACE_ERROR(sync_hyper_call, "kX86SetSegmentES index=%u rpi=%u ti=%u",
        state.seg.es.index, state.seg.es.rpi, state.seg.es.ti);
    break;

  case SyncHyperCall::kX86SetSegmentSS:
    STRACE_ERROR(sync_hyper_call, "kX86SetSegmentSS index=%u rpi=%u ti=%u",
        state.seg.es.index, state.seg.es.rpi, state.seg.es.ti);
    break;

  case SyncHyperCall::kX86SetSegmentDS:
    STRACE_ERROR(sync_hyper_call, "kX86SetSegmentDS index=%u rpi=%u ti=%u",
        state.seg.es.index, state.seg.es.rpi, state.seg.es.ti);
    break;

  case SyncHyperCall::kX86SetSegmentGS:
    if (kLinuxMinIndexForTLSInGDT <= state.seg.gs.index
        && kLinuxMaxIndexForTLSInGDT >= state.seg.gs.index) {
      auto index = state.seg.gs.index;
      state.addr.gs_base.dword = task.tls_slots[index
          - kLinuxMinIndexForTLSInGDT].base_addr;
    } else {
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentGS index=%u rpi=%u ti=%u",
          state.seg.gs.index, state.seg.gs.rpi, state.seg.gs.ti);
    }
    break;

  case SyncHyperCall::kX86SetSegmentFS:
    if (kLinuxMinIndexForTLSInGDT <= state.seg.fs.index
        && kLinuxMaxIndexForTLSInGDT >= state.seg.fs.index) {
      auto index = state.seg.fs.index;
      state.addr.fs_base.dword = task.tls_slots[index
          - kLinuxMinIndexForTLSInGDT].base_addr;
      STRACE_ERROR(sync_hyper_call,
          "kX86SetSegmentFS index=%u rpi=%u ti=%u fsbase=%x", index,
          state.seg.fs.rpi, state.seg.fs.ti, state.addr.fs_base.dword);
    } else {
      STRACE_ERROR(sync_hyper_call, "kX86SetSegmentFS index=%u rpi=%u ti=%u",
          state.seg.fs.index, state.seg.fs.rpi, state.seg.fs.ti);
    }
    break;

  case SyncHyperCall::kX86CPUID: {
    auto eax = state.gpr.rax.dword;
    auto ecx = state.gpr.rcx.dword;

    state.gpr.rax.aword = 0;
    state.gpr.rbx.aword = 0;
    state.gpr.rcx.aword = 0;
    state.gpr.rdx.aword = 0;
    STRACE_ERROR(sync_hyper_call,
        "kX86CPUID eax=%x ecx=%x -> eax=0 ebx=0 ecx=0 edx=0", eax, ecx);
    break;
  }

  case SyncHyperCall::kX86ReadTSC:
    state.gpr.rax.aword = static_cast<uint32_t>(task.time_stamp_counter);
    state.gpr.rdx.aword = static_cast<uint32_t>(task.time_stamp_counter >> 32);
    STRACE_SUCCESS(sync_hyper_call, "kX86ReadTSC eax=%x edx=%x",
        state.gpr.rax.dword, state.gpr.rdx.dword);
    break;

  case SyncHyperCall::kX86ReadTSCP:
    state.gpr.rax.aword = static_cast<uint32_t>(task.time_stamp_counter);
    state.gpr.rdx.aword = static_cast<uint32_t>(task.time_stamp_counter >> 32);
    state.gpr.rcx.aword = 0;  // Processor 0.
    break;

  case SyncHyperCall::kX86EmulateInstruction:
  case SyncHyperCall::kAMD64EmulateInstruction:
    STRACE_ERROR(sync_hyper_call,
        "Unsupported instruction at %" PRIxADDR, state.gpr.rip.aword);
    task.location = kTaskStoppedAtUnsupportedInstruction;
    task.last_pc = CurrentPC(state);
    // how to add pausing here?? With time stamp counter??
    abort();
    break;

  default:
    abort();
  }

  return mem;
}

}  // extern C
