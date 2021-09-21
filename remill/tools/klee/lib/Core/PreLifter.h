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

#ifndef TOOLS_KLEE_LIB_CORE_PRELIFTER_H_
#define TOOLS_KLEE_LIB_CORE_PRELIFTER_H_

#include "llvm/IR/Module.h"

#include "remill/BC/Util.h"
#include "remill/BC/Optimizer.h"
#include <thread>

namespace remill {
class Instruction;
class TraceLifter;
class TraceManager;
}

namespace llvm {
class LLVMContext;
class Module;
}

namespace klee {
class Executor;

namespace native {
class AddressSpace;
class TraceManager;

struct alignas(64) Worker {
public:
  std::shared_ptr<llvm::Module> map_semantics;
  std::vector<uint64_t> traces;
  std::thread thread;

  Worker(llvm::LLVMContext *ctx) :
      /* Jiaqi */
      // map_semantics(remill::LoadTargetSemantics(ctx)) {
      map_semantics(remill::LoadTargetSemantics(*ctx)) {
      /* /Jiaqi */
  }
};

class PreLifter {
  friend class klee::Executor;
public:
  PreLifter(llvm::LLVMContext *context_);
  ~PreLifter() = default;
  static void LiftMapping(Worker *worker, PreLifter *pre_lifter,
      klee::native::AddressSpace *memory);

  void RecursiveDescentPass(const MappedRange &map,
      std::vector<std::pair<uint64_t, bool>> &decoder_work_list);

  void LinearSweepPass(const MappedRange &map,
      std::vector<std::pair<uint64_t, bool>> &decoder_work_list,
      std::unordered_set<uint64_t> &trace_batch);

  void preLift(void);

  void decodeAndMarkTraces(const MemoryMapPtr &map,
      std::unordered_map<uint64_t, llvm::Function *> &new_marked_traces);

  void decodeAndLiftMappings(void);

private:
  llvm::LLVMContext *ctx;
  TraceManager *trace_manager;
  std::vector<std::unique_ptr<Worker>> workers;
};

}
}

#endif /* TOOLS_KLEE_LIB_CORE_PRELIFTER_H_ */
