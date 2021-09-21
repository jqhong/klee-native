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

#include "runtime/Native/OS/Linux/SystemCall.cpp"

// 64-bit `svc` system call ABI.
class AArch64SupervisorCall : public SystemCallABI<AArch64SupervisorCall> {
 public:
  ~AArch64SupervisorCall(void) = default;

  addr_t GetPC(const State *state) const  {
    return state->gpr.pc.aword;
  }

  void SetPC(State *state, addr_t new_pc) const  {
    state->gpr.pc.aword = new_pc;
  }

  void SetSP(State *state, addr_t new_sp) const {
    state->gpr.sp.aword = new_sp;
  }

  addr_t GetReturnAddress(Memory *, State *, addr_t ret_addr) const {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const {
    return state->gpr.x8.qword;
  }

  Memory *DoSetReturn(Memory *memory, State *state,
                    addr_t ret_val) const {
    state->gpr.x0.qword = ret_val;
    return memory;
  }

  bool CanReadArgs(Memory *, State *, int num_args) const {
    return num_args <= 6;
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const {
    switch (i) {
      case 0:
        return state->gpr.x0.qword;
      case 1:
        return state->gpr.x1.qword;
      case 2:
        return state->gpr.x2.qword;
      case 3:
        return state->gpr.x3.qword;
      case 4:
        return state->gpr.x4.qword;
      case 5:
        return state->gpr.x5.qword;
      default:
        return 0;
    }
  }
};

inline static addr_t CurrentPC(AArch64State &state) {
  return state.gpr.pc.aword;
}

extern "C" {

Memory *__remill_sync_hyper_call(AArch64State &, Memory *memory, SyncHyperCall::Name) {
  abort();
  return memory;
}

Memory *__remill_async_hyper_call(
    State &state, addr_t ret_addr, Memory *memory) {
  abort();
  return memory;
}


Memory * __remill_write_memory_8(Memory *mem, addr_t addr, uint8_t val);
 
extern "C" uint8_t __remill_read_8(Memory *mem, addr_t addr);

uint8_t __remill_read_memory_8(Memory *mem, addr_t addr){
  addr = klee_get_value_i64(addr);
  return __remill_read_8(mem, addr);
}

Memory * __remill_write_memory_16(Memory *mem, addr_t addr, uint16_t val) {
  mem = __remill_write_memory_8(mem, addr, static_cast<uint8_t>(val));
  mem = __remill_write_memory_8(mem, addr+1, static_cast<uint8_t>(val >> 8));
  return mem;
}

uint16_t __remill_read_memory_16(Memory *mem, addr_t addr) {
  uint8_t b0 = __remill_read_memory_8(mem, addr);
  uint8_t b1 = __remill_read_memory_8(mem, addr + 1);
  return (static_cast<uint16_t>(b1) << static_cast<uint16_t>(8)) | b0;
}

Memory * __remill_write_memory_32(Memory *mem, addr_t addr, uint32_t val) {
  mem = __remill_write_memory_16(mem, addr, static_cast<uint16_t>(val));
  mem = __remill_write_memory_16(mem, addr+2, static_cast<uint16_t>(val >> 16));
  return mem;
}

uint32_t __remill_read_memory_32(Memory *mem, addr_t addr) {
  uint16_t b0 = __remill_read_memory_16(mem, addr);
  uint16_t b1 = __remill_read_memory_16(mem, addr + 2);
  return (static_cast<uint32_t>(b1) << static_cast<uint32_t>(16)) | b0;
}

Memory * __remill_write_memory_64(Memory *mem, addr_t addr, uint64_t val) {
  mem = __remill_write_memory_32(mem, addr, static_cast<uint32_t>(val));
  mem = __remill_write_memory_32(mem, addr + 4, static_cast<uint32_t>(val >> 32));
  return mem;
}

uint64_t __remill_read_memory_64(Memory *mem, addr_t addr) {
  uint32_t b0 = __remill_read_memory_32(mem, addr);
  uint32_t b1 = __remill_read_memory_32(mem, addr + 4);
  return (static_cast<uint64_t>(b1) << static_cast<uint64_t>(32))| b0;
}

}  // extern C
