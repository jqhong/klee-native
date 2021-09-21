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
#ifndef KLEE_NATIVE_CONTINUATIONS_H
#define KLEE_NATIVE_CONTINUATIONS_H

#include "Executor.h"

namespace klee {
class ExecutionState;
enum class MemoryContinuationKind {
  kContinueRead8,
  kContinueRead16,
  kContinueRead32,
  kContinueRead64,

  kContinueWrite8,
  kContinueWrite16,
  kContinueWrite32,
  kContinueWrite64
};

class StateContinuation {
 public:
  virtual ~StateContinuation(void) = default;
  virtual ExecutionState *YieldNextState(Executor &exe) = 0;


  std::unique_ptr<ExecutionState> state;

  inline explicit StateContinuation(ExecutionState *state_)
      : state(state_) {}

 private:
  StateContinuation(void) = delete;
};

union MemoryReadResult {
  uint8_t as_bytes[8];
  uint64_t as_qword;
  uint32_t as_dword;
  uint16_t as_word;
  uint8_t as_byte;
};

static_assert(sizeof(MemoryReadResult) == sizeof(uint64_t),
              "Invalid packing of `union MemoryReadResult`.");

static_assert(!__builtin_offsetof(MemoryReadResult, as_dword),
              "Invalid packing of `union MemoryReadResult`.");

static_assert(!__builtin_offsetof(MemoryReadResult, as_word),
              "Invalid packing of `union MemoryReadResult`.");

static_assert(!__builtin_offsetof(MemoryReadResult, as_byte),
              "Invalid packing of `union MemoryReadResult`.");


class MemoryAccessContinuation : public StateContinuation {
 public:
  const ref<Expr> addr;
  const uint64_t min_addr;
  const uint64_t max_addr;
  uint64_t next_addr;
  const MemoryContinuationKind kind;

  const uint64_t memory_index;
  const ref<Expr> memory;
  ref<Expr> val_to_write;

  virtual ~MemoryAccessContinuation(void) = default;

  MemoryAccessContinuation(ExecutionState *state, ref<Expr> addr,
                           uint64_t min_val, uint64_t max_val,
                           uint64_t next_val, uint64_t memory_index_,
                           ref<Expr> memory_, MemoryContinuationKind kind_);

  ExecutionState *YieldNextState(Executor &exe) override;
};

class NullContinuation : public StateContinuation {
 public:
  using StateContinuation::StateContinuation;

  virtual ~NullContinuation(void) = default;
  ExecutionState *YieldNextState(Executor &exe) override;
};

class BranchContinuation : public StateContinuation {
 public:
  virtual ~BranchContinuation(void) = default;
  BranchContinuation(ExecutionState *disabled_state_,
                     std::vector<ExecutionState *> &states_);
  ExecutionState *YieldNextState(Executor &exe) override;

 private:
  ExecutionState * const disabled_state;
  std::vector<ExecutionState *> states;
};

}  //  klee namespace
#endif 
