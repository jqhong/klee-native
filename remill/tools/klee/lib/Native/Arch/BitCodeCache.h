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

#ifndef TOOLS_KLEE_LIB_NATIVE_ARCH_BITCODECACHE_H_
#define TOOLS_KLEE_LIB_NATIVE_ARCH_BITCODECACHE_H_
#include "llvm/IR/Module.h"
#include <unordered_set>
#include <vector>
namespace llvm {
class Module;
class Function;
class LLVMContext;
}

namespace klee {
class Executor;

namespace native {
class TraceManager;
class Workspace;
class AddressSpace;

class BitCodeCache {
public:
  inline BitCodeCache(void) = default;
  ~BitCodeCache(void) = default;
  void StoreToWorkspace(llvm::Module &module,
      klee::native::AddressSpace *memory, klee::Executor *exe);
  void LoadFromWorkspace(klee::native::AddressSpace *memory,
      klee::Executor *exe);
  void DestroyFunctions(llvm::Module &module);


  std::unordered_set<uint64_t> materialized_traces;
};
} //  namespace native
} //  namespace klee

#endif /* TOOLS_KLEE_LIB_NATIVE_ARCH_BITCODECACHE_H_ */
