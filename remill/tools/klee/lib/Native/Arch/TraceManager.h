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


#include "remill/BC/Lifter.h"
#include "Native/Arch/BitCodeCache.h"
#include "remill/BC/Util.h"
#include <memory>

namespace klee {

class Executor;

namespace native {

class AddressSpace;
class PolicyHandler;

class TraceManager : public ::remill::TraceManager {
 friend class BitCodeCache;
 friend class Executor;
 friend class PreLifter;
 public:
  explicit TraceManager(llvm::Module &lifted_code_,
      std::shared_ptr<PolicyHandler> ph);

  ~TraceManager(void) = default;

  void ForEachDevirtualizedTarget(
      const remill::Instruction &inst,
      std::function<void(uint64_t, remill::DevirtualizedTargetKind)> func)
          override;

  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) override;

  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) override;

  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) override;

  void MarkAsTraceHead(uint64_t pc);


 protected:
  void SetLiftedTraceDefinition(
      uint64_t addr, llvm::Function *lifted_func) override;

 private:
  friend class ::klee::Executor;

  llvm::Module &lifted_code;
  AddressSpace *memory;
  std::unordered_map<uint64_t, llvm::Function *> traces;
  std::shared_ptr<PolicyHandler> policy_handler;

};
}  // namespace native
}  // namespace klee
