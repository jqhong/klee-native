/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <glog/logging.h>
#include <Native/Memory/AddressSpace.h>
#include <Native/Memory/AllocList.h>
#include <Native/Memory/PolicyHandler.h>
#include <Core/Memory.h>
#include <Core/AddressSpace.h>
#include <Core/Executor.h>
#include <Core/MemoryManager.h>
#include <klee/ExecutionState.h>
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/System/MemoryUsage.h"
#include <llvm/Support/raw_ostream.h>

#include <llvm/IR/Instructions.h>

namespace klee {
namespace native {

ReportErrorPolicyHandler::ReportErrorPolicyHandler() :
    PolicyHandler(), exe(nullptr), st(nullptr) {
}

void ReportErrorPolicyHandler::Init(klee::Executor *exe_) {
  exe = exe_;
}

void ReportErrorPolicyHandler::setState(klee::ExecutionState *state) {
  st = state;
}

klee::ExecutionState *ReportErrorPolicyHandler::getState() {
  return st;
}

klee::Executor *ReportErrorPolicyHandler::getExecutor() {
  return exe;
}

bool ReportErrorPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Heap address overflow on memory write address " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Heap address underflow on memory write address " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem,
    const Address& address, uint8_t *byte_out, bool *res,
    AllocList *alloc_list) {
  LOG(ERROR) << "Heap address overflow on memory read address " << std::hex
      << address.flat << std::dec;
  *byte_out = 0;
  return true;
}

bool ReportErrorPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Heap address underflow on memory read address " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapRead(
    AddressSpace *mem, const Address& address, bool *res,
    AllocList *alloc_list) {
  LOG(ERROR) << "Invalid memory read address " << std::hex << address.flat
      << std::dec << "; out-of-bounds allocation index";
  return true;
}

bool ReportErrorPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(
    AddressSpace *mem, const Address& address, bool *res,
    AllocList *alloc_list) {
  LOG(ERROR) << "Invalid memory write address " << std::hex << address.flat
      << std::dec << "; out-of-bounds allocation index";
  return true;
}

bool ReportErrorPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Use-after-free on memory read addresss " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Use-after-free on memory write addresss " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Error in memory implementation; pseudo-use-after-free on "
      << std::hex << address.flat << std::dec << " (size=" << address.size
      << ", entry=" << address.alloc_index << ")";
  return false;
}

bool ReportErrorPolicyHandler::HandleDoubleFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = true;
  LOG(ERROR) << "Double free on " << std::hex << address.flat << std::dec
      << " (size=" << address.size << ", entry=" << address.alloc_index
      << ")";
  return true;  // To let it continue.
}

bool ReportErrorPolicyHandler::HandleFreeOffset(AddressSpace *mem,
    Address& address, bool *res) {
  *res = true;
  if (address.offset != 0) {
    LOG(ERROR) << "Freeing internal pointer " << std::hex << address.flat
        << std::dec;
    address.offset = 0;
    // TODO(sai): Eventually do something more interesting here.
    return true;
  }
}

bool ReportErrorPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  LOG(ERROR) << "Free of unallocated memory (size=" << address.size
      << ", entry=" << address.alloc_index << ")";
  return true;
}

bool ReportErrorPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem,
    const Address& address, bool *res) {
  LOG(ERROR) << "Trying to execute heap-allocated memory at " << std::hex
      << address.flat << std::dec;
  return true;
}

bool ReportErrorPolicyHandler::HandleBadRealloc(AddressSpace *mem,
    const Address& address, size_t alloc_size, uint64_t err_type,
    AllocList *alloc_list) {
  switch (err_type) {
  case (kReallocInternalPtr): {
    // TODO(sai): Report?
      LOG(ERROR) << "Realloc of internal pointer with size " << address.size
          << ", index " << address.alloc_index << ", and offset " << std::hex
          << address.offset << std::dec;
      return true;
  }
  case (kReallocTooBig): {
      LOG(ERROR) << "Realloc of size " << address.size << " to " << alloc_size
          << " has to be handled by native.";
      return true;
  }
  case (kReallocInvalidPtr): {
      LOG(ERROR) << "Bad old realloc address";
      return true;
  }
  case (kReallocFreedPtr): {
      LOG(ERROR) << "Cannot realloc on a freed memory region";
      return true;
  }
  }
  return err_type;
}

ProxyPolicyHandler::ProxyPolicyHandler() :
    proxy(new ReportErrorPolicyHandler()) {
}

void ProxyPolicyHandler::Init(klee::Executor *exe_) {
  proxy->Init(exe_);
}

void ProxyPolicyHandler::setState(klee::ExecutionState *state) {
  proxy->setState(state);
}

klee::Executor *ProxyPolicyHandler::getExecutor() {
  return proxy->getExecutor();
}

klee::ExecutionState *ProxyPolicyHandler::getState() {
  return proxy->getState();
}

bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleInvalidOutOfBoundsHeapRead(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleInvalidOutOfBoundsHeapWrite(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  KInstruction *ins = getState()->prevPC;
  return proxy->HandleHeapWriteOverflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapWriteUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleHeapWriteUnderflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapReadOverflow(AddressSpace *mem,
    const Address& address, uint8_t *byte_out, bool *res,
    AllocList *alloc_list) {
  return proxy->HandleHeapReadOverflow(mem, address, byte_out, res, alloc_list);
}

bool ProxyPolicyHandler::HandleHeapReadUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleHeapReadUnderflow(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleReadUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleReadUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleWriteUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleWriteUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandlePseudoUseAfterFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandlePseudoUseAfterFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleDoubleFree(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleDoubleFree(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleFreeOffset(AddressSpace *mem, Address& address,
    bool *res) {
  return proxy->HandleFreeOffset(mem, address, res);
}

bool ProxyPolicyHandler::HandleFreeUnallocatedMem(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return proxy->HandleFreeUnallocatedMem(mem, address, res, alloc_list);
}

bool ProxyPolicyHandler::HandleTryExecuteHeapMem(AddressSpace *mem,
    const Address& address, bool *res) {
  return proxy->HandleTryExecuteHeapMem(mem, address, res);
}

bool ProxyPolicyHandler::HandleBadRealloc(AddressSpace *mem,
    const Address& address, size_t alloc_size, uint64_t err_type,
    AllocList *alloc_list) {
  return proxy->HandleBadRealloc(mem, address, alloc_size, err_type, alloc_list);
}

bool SymbolicBufferPolicy::HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}
bool SymbolicBufferPolicy::HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  *res = false;
  return false;
}

bool SymbolicBufferPolicy::HandleHeapWriteOverflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  static const constexpr uint64_t policy_array_size = 100;

    *res = true;
    auto *exe = getExecutor();
    auto state = getState();
    if (!state->policy_buff_array) {
      auto mo = exe->memory->allocate(policy_array_size, false, true,
          state->prevPC->inst, 8);
      exe->executeMakeSymbolic(*state, mo, "symbolic_policy_buffer");
      for (auto &sym_pairs : state->symbolics) {
        if (sym_pairs.first->address == mo->address) {
          state->policy_buff_array = sym_pairs.second;
        }
      }
    }
    auto byte = ReadExpr::create(UpdateList(state->policy_buff_array, 0),
        ConstantExpr::alloc(state->policy_buff_index,
            state->policy_buff_array->getDomain()));
    byte->dump();
    LOG(ERROR) << "Symbolic Heap Overflow on write";
    mem->symbolic_memory[address.flat] = byte;
    state->policy_buff_index = (state->policy_buff_index + 1)
        % policy_array_size;
    return true;
}

bool SymbolicBufferPolicy::HandleHeapWriteUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}

bool SymbolicBufferPolicy::HandleHeapReadOverflow(AddressSpace *mem,
    const Address& address, uint8_t *byte_out, bool *res,
    AllocList *alloc_list) {
  return false;
}

bool SymbolicBufferPolicy::HandleHeapReadUnderflow(AddressSpace *mem,
    const Address& address, bool *res, AllocList *alloc_list) {
  return false;
}

}  //  namespace native
}  //  namespace klee

