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

#include "glog/logging.h"
#include "Native/Workspace/Workspace.h"
#include "Native/Arch/TraceManager.h"
#include "Native/Memory/AddressSpace.h"

#include "Core/Executor.h"

#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/CallSite.h"
#include <llvm/Support/raw_ostream.h>

#include "remill/BC/Util.h"

#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>

#include "remill/OS/FileSystem.h"

#include <llvm/Support/SourceMgr.h>
#include <iostream>

namespace klee {

class Executor;

namespace native {
void BitCodeCache::DestroyFunctions(llvm::Module &module) {
  std::vector<llvm::Function *> rv;
  for (auto &func : module) {
    func.deleteBody();
  }
}

void BitCodeCache::StoreToWorkspace(llvm::Module &module,
    klee::native::AddressSpace *memory, klee::Executor *exe) {
  const auto& cache_path = klee::native::Workspace::BitcodeCachePath();
  for (const auto &trace : materialized_traces) {
    //LOG(INFO) << "throwing away " << std::hex << trace << std::dec;
    std::stringstream ss;
    ss << "sub_" << std::hex << trace << std::dec;
    const auto &name = ss.str();
    auto func = module.getFunction(name);
    func->deleteBody();
  }

  for (auto& mod: memory->aot_traces) {
    DestroyFunctions(*mod.second);
  }

  remill::StoreModuleToFile(&module, cache_path, false);
}

void BitCodeCache::LoadFromWorkspace(klee::native::AddressSpace *memory,
    klee::Executor *exe) {
  const auto &cache_path = Workspace::BitcodeCachePath();
  if (remill::FileExists(cache_path)) {
    remill::LoadModuleFromFile(&exe->semantics_module->getContext(),
        cache_path);
  }
  if (exe->preLift) {
    const auto path = Workspace::PreLiftedTraces();
    auto dir = opendir(path.c_str());
    if (dir == nullptr) {
      LOG(INFO) << "Could not load traces from pre lifted traces at  " << path;
      return;
    }

    while (auto ent = readdir(dir)) {
      if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
        continue;
      }
      std::stringstream ss;
      std::stringstream addr_stream;
      uint64_t map_label;
      ss << path << "/" << ent->d_name;
      auto name = std::string(ent->d_name);
      name = name.substr(0, name.find("-"));
      //LOG(INFO) << "name is " << name;
      addr_stream << "0x" << name;
      addr_stream >> std::hex >> map_label;
      auto page_name = ss.str();
      memory->aot_traces[page_name] = std::shared_ptr<llvm::Module>(
          remill::LoadModuleFromFile(&exe->semantics_module->getContext(),
              page_name, true));
    }

    closedir(dir);
  }
}

} //  namespace native
} // namespace klee
