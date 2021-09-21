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

#include "TraceManager.h"

#include <glog/logging.h>

#include "Native/Memory/AddressSpace.h"

namespace klee {
namespace native {

TraceManager::TraceManager(llvm::Module &lifted_code_,
    std::shared_ptr<PolicyHandler> ph)
    : lifted_code(lifted_code_),
      memory(nullptr),
      policy_handler(ph) {}


void TraceManager::ForEachDevirtualizedTarget(
    const remill::Instruction &inst,
    std::function<void(uint64_t, remill::DevirtualizedTargetKind)> func) {}

bool TraceManager::TryReadExecutableByte(uint64_t addr, uint8_t *byte) {
  DLOG_IF(FATAL, !memory) << "Memory pointer not initialized in TraceManager.";
  return memory->TryReadExecutable(addr, byte, policy_handler.get());
}

void TraceManager::SetLiftedTraceDefinition(uint64_t addr,
                                            llvm::Function *lifted_func) {
  traces[addr] = lifted_func;
}

llvm::Function *TraceManager::GetLiftedTraceDeclaration(uint64_t addr) {
  auto trace_it = traces.find(addr);
  if (trace_it != traces.end()) {
    return trace_it->second;
  } else {
    return nullptr;
  }
}

llvm::Function *TraceManager::GetLiftedTraceDefinition(uint64_t addr) {
  return GetLiftedTraceDeclaration(addr);
}

void TraceManager::MarkAsTraceHead(uint64_t pc) {
  DLOG_IF(FATAL, !memory) << "Memory pointer not initialized in TraceManager.";
  memory->MarkAsTraceHead(pc);
}

}  // namespace native
}  // namespace klee
