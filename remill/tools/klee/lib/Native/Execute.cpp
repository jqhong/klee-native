
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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <sys/stat.h>
#include "remill/Arch/Arch.h"

#include "Native/Workspace/Workspace.h"
#include "Native/Memory/Snapshot.h"
#include "Native/Memory/AddressSpace.h"
#include "Native/Memory/PolicyHandler.h"

#include "klee/klee.h"
#include "klee/Interpreter.h"
#include "klee/Expr.h"
#include "klee/ExecutionState.h"
#include "klee/Internal/Support/Debug.h"

#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Internal/Support/FileHandling.h"
#include "klee/Internal/Support/ModuleUtil.h"

#include "klee/Config/Version.h"
#include "klee/Internal/ADT/KTest.h"
#include "klee/Internal/ADT/TreeStream.h"                                                                        
#include "klee/Statistics.h"

#include <llvm/Support/CrashRecoveryContext.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Errno.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Signals.h"

#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

#include <memory>
#include <cxxabi.h>
#include <sstream>

DECLARE_string(os);
DECLARE_string(arch);
DEFINE_bool(symbolic_stdin, false, "bool set if stdin is symbolic");
DEFINE_bool(pre_lift, false, "bool set if traces should be lifted ahead of time");

class NativeHandler : public klee::InterpreterHandler {
 public:
  NativeHandler(void);

  virtual ~NativeHandler(void) = default;

  void setInterpreter(klee::Interpreter *i);

  llvm::raw_ostream &getInfoStream(void) const override {
    return *info_file;
  }

  uint64_t getNumPathsExplored() {
    return paths_explored;
  }

  void incPathsExplored() override {
    paths_explored++;
  }

  std::string getOutputFilename(const std::string &filename) override;

  std::unique_ptr<llvm::raw_fd_ostream> openOutputFile(
      const std::string &filename) override;

  void processTestCase(const klee::ExecutionState &state, const char *err,
                       const char *suffix) override;

 private:
  klee::Interpreter *interpreter;

  uint64_t paths_explored;

  std::unique_ptr<llvm::raw_ostream> info_file;
};

NativeHandler::NativeHandler(void)
    : klee::InterpreterHandler(),
      interpreter(0),
      paths_explored(0) {

  info_file = openOutputFile("info");
}

void NativeHandler::setInterpreter(klee::Interpreter *i) {
  interpreter = i;
}

std::string NativeHandler::getOutputFilename(const std::string &filename) {
  llvm::SmallString<128> path("./");
  llvm::sys::path::append(path, filename);
  return path.str();
}

std::unique_ptr<llvm::raw_fd_ostream> NativeHandler::openOutputFile(
    const std::string &filename) {
  std::string Error;
  std::string path = getOutputFilename(filename);
  auto f = klee::klee_open_output_file(path, Error);
  if (!f) {
    LOG(FATAL)
        << "error opening file \"%s\".  KLEE may have run out of file "
        << "descriptors: try to increase the maximum number of open file "
        << "descriptors by using ulimit (%s).";
    return nullptr;
  }
  return f;
}

void NativeHandler::processTestCase(const klee::ExecutionState &state,
                                   const char *err, const char *suffix) {
  return;
}


#define LIBKLEE_PATH  "libklee-libc.bca"

static llvm::Module *LoadRuntimeBitcode(llvm::LLVMContext *context) {

  struct stat cache_stat;
  std::string runtime_bitcode_path;
  if ((stat(klee::native::Workspace::BitcodeCachePath().c_str(), &cache_stat) == 0)){
    runtime_bitcode_path = klee::native::Workspace::BitcodeCachePath();
    LOG(INFO)
        << "Loading bitcode cache from " << runtime_bitcode_path;
  } else {
    runtime_bitcode_path = klee::native::Workspace::RuntimeBitcodePath();
    LOG(INFO)
        << "Loading runtime bitcode file from " << runtime_bitcode_path;
  }

  /* Jiaqi */
  // return remill::LoadModuleFromFile(
  //     context, runtime_bitcode_path, false /* allow_failure */);
  return remill::LoadModuleFromFile(
      context, runtime_bitcode_path, false /* allow_failure */).get();
  /* /Jiaqi */
}

int main(int argc, char **argv, char **envp) {
  llvm::InitializeAllTargets();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmPrinters();
  llvm::InitializeAllAsmParsers();
  llvm::CrashRecoveryContext::Enable();

  std::stringstream ss;
  ss << std::endl << std::endl << "  " << argv[0] << " \\" << std::endl
     << "    --workspace_dir WORKSPACE_DIR \\" << std::endl << "    ..."
     << std::endl;

  google::ParseCommandLineFlags(&argc, &argv, true);
  google::SetUsageMessage(ss.str());

  google::InitGoogleLogging(argv[0]);
  google::InstallFailureSignalHandler();

  auto snapshot = klee::native::LoadSnapshotFromFile(
      klee::native::Workspace::SnapshotPath());

  // Take in the OS and arch names from the snapshot.
  FLAGS_os = snapshot->os();
  FLAGS_arch = snapshot->arch();
  FLAGS_logtostderr = true;

  //Make sure that we support the snapshotted arch/os combination.
  /* Jiaqi */
  // CHECK(remill::GetTargetArch() != nullptr)
  //     << "Can't find architecture for " << FLAGS_os << " and "
  //     << FLAGS_arch;

  llvm::LLVMContext context;
  CHECK(remill::GetTargetArch(context) != nullptr)
      << "Can't find architecture for " << FLAGS_os << " and "
      << FLAGS_arch;
  /* /Jiaqi */
  std::vector<std::unique_ptr<llvm::Module>> loaded_modules;

  loaded_modules.emplace_back(LoadRuntimeBitcode(&context));

  klee::Interpreter::ModuleOptions module_options(
      "",
      "main"  /* Entrypoint */,
      true  /* Optimize */,
      false  /* Check div by zero */,
      false  /* Check overshift */);

  klee::Interpreter::InterpreterOptions interp_options;
  interp_options.MakeConcreteSymbolic = false;
  auto intercept_path = klee::native::Workspace::RuntimeInterceptPath();
  
  std::unique_ptr<NativeHandler> handler(new NativeHandler());
  auto executor =
      klee::Interpreter::create(context, interp_options, handler.get());

  handler->setInterpreter(executor);

  auto policy_handler = new klee::native::SymbolicBufferPolicy();
  executor->setModule(loaded_modules, module_options, policy_handler);


  klee::native::Workspace::LoadSnapshotIntoExecutor(snapshot, executor);
  executor->setSymbolicStdin(FLAGS_symbolic_stdin);
  executor->setPreLift(FLAGS_pre_lift);

  executor->Run();

  delete executor;

  // TODO(pag,sai): Freeing the `executor` causes a segfault.

  google::ShutdownGoogleLogging();
  google::ShutDownCommandLineFlags();
  llvm::llvm_shutdown();

  return EXIT_SUCCESS;
}
