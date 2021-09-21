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
#pragma once

namespace klee {
class Executor;
class ExecutionState;

namespace native {
class AddressSpace;
class AllocList;
union Address;

class PolicyHandler {
public:
  PolicyHandler() = default;
  virtual ~PolicyHandler() = default;
  virtual void Init(klee::Executor *exe_) = 0;
  virtual void setState(klee::ExecutionState *state) = 0;
  virtual klee::Executor *getExecutor() = 0;
  virtual klee::ExecutionState *getState() = 0;
  virtual bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleHeapWriteOverflow(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleHeapWriteUnderflow(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleHeapReadUnderflow(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleReadUseAfterFree(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleWriteUseAfterFree(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandlePseudoUseAfterFree(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleDoubleFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleFreeOffset(AddressSpace *mem, Address& address, bool *res) = 0;
  virtual bool HandleFreeUnallocatedMem(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) = 0;
  virtual bool HandleTryExecuteHeapMem(AddressSpace *mem,
      const Address& address, bool *res ) = 0;
  virtual bool HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type, AllocList *alloc_list) = 0;

};

class ReportErrorPolicyHandler: public PolicyHandler {
public:
  ReportErrorPolicyHandler();
  void Init(klee::Executor *exe_) override;
  void setState(klee::ExecutionState *state) override;
  klee::Executor *getExecutor() override;
  klee::ExecutionState *getState() override;
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleReadUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleWriteUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandlePseudoUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleDoubleFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleFreeOffset(AddressSpace *mem, Address& address, bool *res ) override;
  bool HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address, bool *res) override;
  bool HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type, AllocList *alloc_list ) override;

  klee::Executor *exe;
  klee::ExecutionState *st;

};

class ProxyPolicyHandler: public PolicyHandler {
public:
  ProxyPolicyHandler();
  void Init(klee::Executor *exe_) override;
  void setState(klee::ExecutionState *state) override;
  klee::ExecutionState *getState() override;
  klee::Executor *getExecutor() override;
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleReadUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleWriteUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandlePseudoUseAfterFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleDoubleFree(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleFreeOffset(AddressSpace *mem, Address& address, bool *res ) override;
  bool HandleFreeUnallocatedMem(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleTryExecuteHeapMem(AddressSpace *mem, const Address& address, bool *res) override;
  bool HandleBadRealloc(AddressSpace *mem, const Address& address,
      size_t alloc_size, uint64_t err_type, AllocList *alloc_list) override;

  std::unique_ptr<PolicyHandler> proxy;
};

class SymbolicBufferPolicy: public ProxyPolicyHandler {
public:
  SymbolicBufferPolicy() = default;
  bool HandleInvalidOutOfBoundsHeapRead(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list);
  bool HandleInvalidOutOfBoundsHeapWrite(AddressSpace *mem,
      const Address& address, bool *res, AllocList *alloc_list);
  bool HandleHeapWriteOverflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapWriteUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadOverflow(AddressSpace *mem, const Address& address,
      uint8_t *byte_out, bool *res, AllocList *alloc_list) override;
  bool HandleHeapReadUnderflow(AddressSpace *mem, const Address& address, bool *res, AllocList *alloc_list) override;
};


} //  namespace native
} //  namespace klee

