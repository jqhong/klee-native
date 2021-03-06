/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <sstream>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef WIN32
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/Annotate.h"
#include "remill/BC/Compat/BitcodeReaderWriter.h"
#include "remill/BC/Compat/DebugInfo.h"
#include "remill/BC/Compat/GlobalValue.h"
#include "remill/BC/Compat/IRReader.h"
#include "remill/BC/Compat/ToolOutputFile.h"
#include "remill/BC/Compat/Verifier.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"
#include "remill/OS/FileSystem.h"

DECLARE_string(arch);

DEFINE_string(semantics_search_paths, "", "Colon-separated list of search paths to use when searching for semantics files.");

namespace {
#ifdef WIN32
    extern "C" std::uint32_t GetProcessId(std::uint32_t handle);
#endif

    // We are avoiding the `getpid` name here to make sure we don't
    // conflict with the (deprecated) getpid function from the Windows
    // ucrt headers
    std::uint32_t nativeGetProcessID(void) {
#ifdef WIN32
        return GetProcessId(0);
#else
        return getpid();
#endif
    }
}  // namespace

namespace remill {

    // Initialize the attributes for a lifted function.
    void InitFunctionAttributes(llvm::Function *function) {

        // Make sure functions are treated as if they return. LLVM doesn't like
        // mixing must-tail-calls with no-return.
        function->removeFnAttr(llvm::Attribute::NoReturn);

        // Don't use any exception stuff.
        function->removeFnAttr(llvm::Attribute::UWTable);
        function->removeFnAttr(llvm::Attribute::NoInline);
        function->addFnAttr(llvm::Attribute::NoUnwind);
        function->addFnAttr(llvm::Attribute::InlineHint);
    }

    // Create a call from one lifted function to another.
    llvm::CallInst *AddCall(llvm::BasicBlock *source_block,
            llvm::Value *dest_func) {
        llvm::IRBuilder<> ir(source_block);
        return ir.CreateCall(dest_func, LiftedFunctionArgs(source_block));
    }

    // Create a tail-call from one lifted function to another.
    llvm::CallInst *AddTerminatingTailCall(llvm::Function *source_func,
            llvm::Value *dest_func) {
        if (source_func->isDeclaration()) {
            llvm::IRBuilder<> ir(
                    llvm::BasicBlock::Create(source_func->getContext(), "", source_func));
        }
        return AddTerminatingTailCall(&(source_func->back()), dest_func);
    }

    llvm::CallInst *AddTerminatingTailCall(llvm::BasicBlock *source_block,
            llvm::Value *dest_func) {
        CHECK(nullptr != dest_func) << "Target function/block does not exist!";

        LOG_IF(ERROR, source_block->getTerminator())
            << "Block already has a terminator; not adding fall-through call to: "
            << (dest_func ? dest_func->getName().str() : "<unreachable>");

        llvm::IRBuilder<> ir(source_block);

        // get the `NEXT_PC` and set it to `PC`
        auto next_pc = LoadNextProgramCounter(source_block);
        auto pc_ref = LoadProgramCounterRef(source_block);
        (void) new llvm::StoreInst(next_pc, pc_ref, source_block);

        auto call_target_instr = AddCall(source_block, dest_func);
        call_target_instr->setTailCall(true);

        ir.CreateRet(call_target_instr);
        return call_target_instr;
    }

    // Find a local variable defined in the entry block of the function. We use
    // this to find register variables.
    llvm::Value *FindVarInFunction(llvm::BasicBlock *block, const std::string &name,
            bool allow_failure) {
        return FindVarInFunction(block->getParent(), name, allow_failure);
    }

    // Find a local variable defined in the entry block of the function. We use
    // this to find register variables.
    llvm::Value *FindVarInFunction(llvm::Function *function,
            const std::string &name, bool allow_failure) {
        if (!function->empty()) {
            for (auto &instr : function->getEntryBlock()) {
                if (instr.getName() == name) {
                    return &instr;
                }
            }
        }

        for (auto &arg : function->args()) {
            if (arg.getName() == name) {
                return &arg;
            }
        }

        auto module = function->getParent();
        if (auto var = module->getGlobalVariable(name)) {
            return var;
        }

        CHECK(allow_failure) << "Could not find variable " << name << " in function "
            << function->getName().str();
        return nullptr;
    }

    // Find the machine state pointer.
    llvm::Value *LoadStatePointer(llvm::Function *function) {
        CHECK(kNumBlockArgs == function->arg_size())
            << "Invalid block-like function. Expected three arguments: state "
            << "pointer, program counter, and memory pointer in function "
            << function->getName().str();

        static_assert(0 == kStatePointerArgNum,
                "Expected state pointer to be the first operand.");

        return NthArgument(function, kStatePointerArgNum);
    }

    // Return the memory pointer argument.
    llvm::Value *LoadMemoryPointerArg(llvm::Function *function) {
        CHECK(kNumBlockArgs == function->arg_size())
            << "Invalid block-like function. Expected three arguments: state "
            << "pointer, program counter, and memory pointer in function "
            << function->getName().str();

        static_assert(2 == kMemoryPointerArgNum,
                "Expected state pointer to be the first operand.");

        return NthArgument(function, kMemoryPointerArgNum);
    }

    // Return the program counter argument.
    llvm::Value *LoadProgramCounterArg(llvm::Function *function) {
        CHECK(kNumBlockArgs == function->arg_size())
            << "Invalid block-like function. Expected three arguments: state "
            << "pointer, program counter, and memory pointer in function "
            << function->getName().str();

        static_assert(1 == kPCArgNum,
                "Expected state pointer to be the first operand.");

        return NthArgument(function, kPCArgNum);
    }

    llvm::Value *LoadStatePointer(llvm::BasicBlock *block) {
        return LoadStatePointer(block->getParent());
    }

    // Return the current program counter.
    llvm::Value *LoadProgramCounter(llvm::BasicBlock *block) {
        llvm::IRBuilder<> ir(block);
        return ir.CreateLoad(LoadProgramCounterRef(block));
    }

    // Return a reference to the current program counter.
    llvm::Value *LoadProgramCounterRef(llvm::BasicBlock *block) {
        return FindVarInFunction(block->getParent(), "PC");
    }

    // Return a reference to the next program counter.
    llvm::Value *LoadNextProgramCounterRef(llvm::BasicBlock *block) {
        return FindVarInFunction(block->getParent(), "NEXT_PC");
    }

    // Return the next program counter.
    llvm::Value *LoadNextProgramCounter(llvm::BasicBlock *block) {
        llvm::IRBuilder<> ir(block);
        return ir.CreateLoad(LoadNextProgramCounterRef(block));
    }

    // Return a reference to the return program counter.
    llvm::Value *LoadReturnProgramCounterRef(llvm::BasicBlock *block) {
        return FindVarInFunction(block->getParent(), "RETURN_PC");
    }

    // Update the program counter in the state struct with a new value.
    void StoreProgramCounter(llvm::BasicBlock *block, llvm::Value *pc) {
        (void) new llvm::StoreInst(pc, LoadProgramCounterRef(block), block);
    }

    // Update the next program counter in the state struct with a new value.
    void StoreNextProgramCounter(llvm::BasicBlock *block, llvm::Value *pc) {
        (void) new llvm::StoreInst(pc, LoadNextProgramCounterRef(block), block);
    }

    // Update the program counter in the state struct with a hard-coded value.
    void StoreProgramCounter(llvm::BasicBlock *block, uint64_t pc) {
        auto pc_ptr = LoadProgramCounterRef(block);
        auto type = llvm::dyn_cast<llvm::PointerType>(pc_ptr->getType());
        (void) new llvm::StoreInst(llvm::ConstantInt::get(type->getElementType(), pc),
                pc_ptr, block);
    }

    // Return the current memory pointer.
    llvm::Value *LoadMemoryPointer(llvm::BasicBlock *block) {
        llvm::IRBuilder<> ir(block);
        return ir.CreateLoad(LoadMemoryPointerRef(block));
    }

    // Return an `llvm::Value *` that is an `i1` (bool type) representing whether
    // or not a conditional branch is taken.
    llvm::Value *LoadBranchTaken(llvm::BasicBlock *block) {
        llvm::IRBuilder<> ir(block);
        auto cond =
            ir.CreateLoad(FindVarInFunction(block->getParent(), "BRANCH_TAKEN"));
        auto true_val = llvm::ConstantInt::get(cond->getType(), 1);
        return ir.CreateICmpEQ(cond, true_val);
    }

    // Return a reference to the branch taken
    llvm::Value *LoadBranchTakenRef(llvm::BasicBlock *block) {
        return FindVarInFunction(block->getParent(), "BRANCH_TAKEN");
    }

    // Return a reference to the memory pointer.
    llvm::Value *LoadMemoryPointerRef(llvm::BasicBlock *block) {
        return FindVarInFunction(block->getParent(), "MEMORY");
    }

    // Find a function with name `name` in the module `M`.
    llvm::Function *FindFunction(llvm::Module *module, const std::string &name) {
        return module->getFunction(name);
    }

    // Find a global variable with name `name` in the module `M`.
    llvm::GlobalVariable *FindGlobaVariable(llvm::Module *module,
            const std::string &name) {
        return module->getGlobalVariable(name, true);
    }

    // Loads the semantics for the `arch`-specific machine, i.e. the machine of the
    // code that we want to lift.
    std::unique_ptr<llvm::Module> LoadArchSemantics(const Arch *arch) {
        auto arch_name = GetArchName(arch->arch_name);
        auto path = FindSemanticsBitcodeFile(arch_name);
        LOG(INFO) << "Loading " << arch_name << " semantics from file " << path;
        auto module = LoadModuleFromFile(arch->context, path);
        arch->PrepareModule(module);
        arch->InitFromSemanticsModule(module.get());
        for (auto &func : *module) {
            Annotate<remill::Semantics>(&func);
        }
        return module;
    }

    // Loads the semantics for the "host" machine, i.e. the machine that this
    // remill is compiled on.
    std::unique_ptr<llvm::Module> LoadHostSemantics(llvm::LLVMContext &context) {
        return LoadArchSemantics(GetHostArch(context));
    }

    // Loads the semantics for the "target" machine, i.e. the machine of the
    // code that we want to lift.
    std::unique_ptr<llvm::Module> LoadTargetSemantics(llvm::LLVMContext &context) {
        return LoadArchSemantics(GetTargetArch(context));
    }

    // Try to verify a module.
    bool VerifyModule(llvm::Module *module) {
        std::string error;
        llvm::raw_string_ostream error_stream(error);
        if (llvm::verifyModule(*module, &error_stream)) {
            error_stream.flush();
            LOG(ERROR) << "Error verifying module read from file: " << error;
            return false;
        } else {
            return true;
        }
    }

    // Reads an LLVM module from a file.
    std::unique_ptr<llvm::Module> LoadModuleFromFile(llvm::LLVMContext *context,
            const std::string &file_name,
            bool allow_failure) {
        llvm::SMDiagnostic err;
        auto module = llvm::parseIRFile(file_name, err, *context);

        if (!module) {
            LOG_IF(FATAL, !allow_failure) << "Unable to parse module file " << file_name
                << ": " << err.getMessage().str();
            return {};
        }

        auto ec = module->materializeAll();  // Just in case.
        if (ec) {
            LOG_IF(FATAL, !allow_failure)
                << "Unable to materialize everything from " << file_name;
            return {};
        }

        if (!VerifyModule(module.get())) {
            LOG_IF(FATAL, !allow_failure)
                << "Error verifying module read from file " << file_name;
            return {};
        }

        return module;
    }

    // Store an LLVM module into a file.
    bool StoreModuleToFile(llvm::Module *module, const std::string &file_name,
            bool allow_failure) {
        DLOG(INFO) << "Saving bitcode to file " << file_name;

        std::stringstream ss;
        ss << file_name << ".tmp." << nativeGetProcessID();
        auto tmp_name = ss.str();

        std::string error;
        llvm::raw_string_ostream error_stream(error);

        if (llvm::verifyModule(*module, &error_stream)) {
            error_stream.flush();
            LOG_IF(FATAL, !allow_failure)
                << "Error writing module to file " << file_name << ": " << error;
            return false;
        }

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 5)
        std::error_code ec;
#  if LLVM_VERSION_NUMBER < LLVM_VERSION(7, 0)
        llvm::ToolOutputFile bc(tmp_name.c_str(), ec, llvm::sys::fs::F_RW);
#  else
        llvm::ToolOutputFile bc(tmp_name.c_str(), ec, llvm::sys::fs::OF_None);
#  endif
        CHECK(!ec) << "Unable to open output bitcode file for writing: " << tmp_name;
#else
        llvm::tool_output_file bc(tmp_name.c_str(), error, llvm::sys::fs::F_RW);
        CHECK(error.empty() && !bc.os().has_error())
            << "Unable to open output bitcode file for writing: " << tmp_name << ": "
            << error;
#endif

#if LLVM_VERSION_NUMBER < LLVM_VERSION(7, 0)
        llvm::WriteBitcodeToFile(module, bc.os());
#else
        llvm::WriteBitcodeToFile(*module, bc.os());
#endif
        bc.keep();
        if (!bc.os().has_error()) {
            MoveFile(tmp_name, file_name);
            return true;

        } else {
            RemoveFile(tmp_name);
            LOG_IF(FATAL, !allow_failure)
                << "Error writing bitcode to file: " << file_name << ".";
            return false;
        }
    }

    // Store a module, serialized to LLVM IR, into a file.
    bool StoreModuleIRToFile(llvm::Module *module, const std::string &file_name,
            bool allow_failure) {

#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 5)
        std::error_code ec;
        llvm::raw_fd_ostream dest(file_name.c_str(), ec, llvm::sys::fs::F_Text);
        auto good = !ec;
        auto error = ec.message();
#else
        std::string error;
        llvm::raw_fd_ostream dest(file_name.c_str(), error, llvm::sys::fs::F_Text);
        auto good = error.empty();
#endif
        if (!good) {
            LOG_IF(FATAL, allow_failure)
                << "Could not save LLVM IR to " << file_name << ": " << error;
            return false;
        }
        module->print(dest, nullptr);
        return true;
    }

    namespace {

#ifndef REMILL_BUILD_SEMANTICS_DIR_X86
#  error \
        "Macro `REMILL_BUILD_SEMANTICS_DIR_X86` must be defined to support X86 and AMD64 architectures."
#  define REMILL_BUILD_SEMANTICS_DIR_X86
#endif  // REMILL_BUILD_SEMANTICS_DIR_X86

#ifndef REMILL_BUILD_SEMANTICS_DIR_AARCH64
#  error \
        "Macro `REMILL_BUILD_SEMANTICS_DIR_AARCH64` must be defined to support AArch64 architecture."
#  define REMILL_BUILD_SEMANTICS_DIR_AARCH64
#endif  // REMILL_BUILD_SEMANTICS_DIR_AARCH64

#ifndef REMILL_INSTALL_SEMANTICS_DIR
#  error "Macro `REMILL_INSTALL_SEMANTICS_DIR` must be defined."
#  define REMILL_INSTALL_SEMANTICS_DIR
#endif  // REMILL_INSTALL_SEMANTICS_DIR

#define _S(x) #x
#define S(x) _S(x)
#define MAJOR_MINOR S(LLVM_VERSION_MAJOR) "." S(LLVM_VERSION_MINOR)

        static const char *gSemanticsSearchPaths[] = {

            // Derived from the build.
            REMILL_BUILD_SEMANTICS_DIR_X86 "\0",
            REMILL_BUILD_SEMANTICS_DIR_AARCH64 "\0",
            REMILL_INSTALL_SEMANTICS_DIR "\0",
            "/usr/local/share/remill/" MAJOR_MINOR "/semantics",
            "/usr/share/remill/" MAJOR_MINOR "/semantics",
            "/share/remill/" MAJOR_MINOR "/semantics",
        };

    }  // namespace

    // Find the path to the semantics bitcode file associated with `FLAGS_arch`.
    std::string FindTargetSemanticsBitcodeFile(void) {
        return FindSemanticsBitcodeFile(FLAGS_arch);
    }

    // Find the path to the semantics bitcode file associated with `REMILL_ARCH`,
    // the architecture on which remill is compiled.
    std::string FindHostSemanticsBitcodeFile(void) {
        return FindSemanticsBitcodeFile(REMILL_ARCH);
    }

    // Find the path to the semantics bitcode file.
    std::string FindSemanticsBitcodeFile(const std::string &arch) {
        if (!FLAGS_semantics_search_paths.empty()) {
            std::stringstream pp;
            pp << FLAGS_semantics_search_paths;
            for (std::string sem_dir; std::getline(pp, sem_dir, ':'); ) {
                std::stringstream ss;
                ss << sem_dir << "/" << arch << ".bc";
                if (auto sem_path = ss.str(); FileExists(sem_path)) {
                    return sem_path;
                }
            }
        }

        for (auto sem_dir : gSemanticsSearchPaths) {
            std::stringstream ss;
            ss << sem_dir << "/" << arch << ".bc";
            if (auto sem_path = ss.str(); FileExists(sem_path)) {
                return sem_path;
            }
        }

        LOG(FATAL) << "Cannot find path to " << arch << " semantics bitcode file.";
        return "";
    }

    namespace {

        // Convert an LLVM thing (e.g. `llvm::Value` or `llvm::Type`) into
        // a `std::string`.
        template <typename T>
            inline static std::string DoLLVMThingToString(T *thing) {
                if (thing) {
                    std::string str;
                    llvm::raw_string_ostream str_stream(str);
                    thing->print(str_stream);
                    return str;
                } else {
                    return "(null)";
                }
            }

    }  // namespace

    std::string LLVMThingToString(llvm::Value *thing) {
        return DoLLVMThingToString(thing);
    }

    std::string LLVMThingToString(llvm::Type *thing) {
        return DoLLVMThingToString(thing);
    }

    llvm::Argument *NthArgument(llvm::Function *func, size_t index) {
        auto it = func->arg_begin();
        if (index >= static_cast<size_t>(std::distance(it, func->arg_end()))) {
            return nullptr;
        }
        std::advance(it, index);
        return &*it;
    }

    // Returns a pointer to the `__remill_basic_block` function.
    llvm::Function *BasicBlockFunction(llvm::Module *module) {
        auto bb = module->getFunction("__remill_basic_block");
        CHECK(nullptr != bb);
        return bb;
    }

    // Return the type of a lifted function.
    llvm::FunctionType *LiftedFunctionType(llvm::Module *module) {
        return BasicBlockFunction(module)->getFunctionType();
    }

    // Return a vector of arguments to pass to a lifted function, where the
    // arguments are derived from `block`.
    std::array<llvm::Value *, kNumBlockArgs>
        LiftedFunctionArgs(llvm::BasicBlock *block) {
            auto func = block->getParent();

            // Set up arguments according to our ABI.
            std::array<llvm::Value *, kNumBlockArgs> args;

            if (FindVarInFunction(func, "PC", true)) {
                args[kMemoryPointerArgNum] = LoadMemoryPointer(block);
                args[kStatePointerArgNum] = LoadStatePointer(block);
                args[kPCArgNum] = LoadProgramCounter(block);
            } else {
                args[kMemoryPointerArgNum] = NthArgument(func, kMemoryPointerArgNum);
                args[kStatePointerArgNum] = NthArgument(func, kStatePointerArgNum);
                args[kPCArgNum] = NthArgument(func, kPCArgNum);
            }

            return args;
        }

    // Apply a callback function to every semantics bitcode function.
    void ForEachISel(llvm::Module *module, ISelCallback callback) {
        for (auto &global : module->globals()) {
            const auto &name = global.getName();
            if (name.startswith("ISEL_") || name.startswith("COND_")) {
                llvm::Function *sem = nullptr;
                if (global.hasInitializer()) {
                    sem = llvm::dyn_cast<llvm::Function>(
                            global.getInitializer()->stripPointerCasts());
                }
                callback(&global, sem);
            }
        }
    }

    // Declare a lifted function of the correct type.
    llvm::Function *DeclareLiftedFunction(llvm::Module *module,
            const std::string &name) {
        auto func = module->getFunction(name);
        if (!func) {
            auto bb = BasicBlockFunction(module);
            auto func_type = bb->getFunctionType();
            func = llvm::Function::Create(func_type, llvm::GlobalValue::InternalLinkage,
                    name, module);
            InitFunctionAttributes(func);
        }

        return func;
    }

    // Returns the type of a state pointer.
    llvm::PointerType *StatePointerType(llvm::Module *module) {
        return llvm::dyn_cast<llvm::PointerType>(
                LiftedFunctionType(module)->getParamType(kStatePointerArgNum));
    }

    // Returns the type of a state pointer.
    llvm::PointerType *MemoryPointerType(llvm::Module *module) {
        return llvm::dyn_cast<llvm::PointerType>(
                LiftedFunctionType(module)->getParamType(kMemoryPointerArgNum));
    }

    // Returns the type of an address (addr_t in the State.h).
    llvm::IntegerType *AddressType(llvm::Module *module) {
        return llvm::dyn_cast<llvm::IntegerType>(
                LiftedFunctionType(module)->getParamType(kPCArgNum));
    }

    // Clone function `source_func` into `dest_func`. This will strip out debug
    // info during the clone.
    void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func) {
        auto new_args = dest_func->arg_begin();
        ValueMap value_map;
        for (llvm::Argument &old_arg : source_func->args()) {
            new_args->setName(old_arg.getName());
            value_map[&old_arg] = &*new_args;
            ++new_args;
        }

        CloneFunctionInto(source_func, dest_func, value_map);
    }

    // Make `func` a clone of the `__remill_basic_block` function.
    void CloneBlockFunctionInto(llvm::Function *func) {
        auto bb_func = BasicBlockFunction(func->getParent());
        CHECK(remill::FindVarInFunction(bb_func, "MEMORY") != nullptr);

        CloneFunctionInto(bb_func, func);

        // Remove the `return` in `__remill_basic_block`.
        auto &entry = func->front();
        auto term = entry.getTerminator();
        CHECK(llvm::isa<llvm::ReturnInst>(term));

        term->eraseFromParent();
        func->removeFnAttr(llvm::Attribute::OptimizeNone);

        CHECK(remill::FindVarInFunction(func, "MEMORY") != nullptr);
    }

    // Returns a list of callers of a specific function.
    std::vector<llvm::CallInst *> CallersOf(llvm::Function *func) {
        std::vector<llvm::CallInst *> callers;
        if (func) {
            for (auto user : func->users()) {
                if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
                    if (call_inst->getCalledFunction() == func) {
                        callers.push_back(call_inst);
                    }
                }
            }
        }
        return callers;
    }

    // Returns the name of a module.
    std::string ModuleName(llvm::Module *module) {
#if LLVM_VERSION_NUMBER < LLVM_VERSION(3, 6)
        return module->getModuleIdentifier();
#else
        return module->getName().str();
#endif
    }

    std::string ModuleName(const std::unique_ptr<llvm::Module> &module) {
        return ModuleName(module.get());
    }

    namespace {

#if 0
        static llvm::Constant *CloneConstant(llvm::Constant *val);

        static std::vector<llvm::Constant *> CloneContents(
                llvm::ConstantAggregate *agg) {
            auto num_elems = agg->getNumOperands();
            std::vector<llvm::Constant *> clones(num_elems);
            for (auto i = 0U; i < num_elems; ++i) {
                clones[i] = CloneConstant(agg->getAggregateElement(i));
            }
            return clones;
        }

        static llvm::Constant *CloneConstant(llvm::Constant *val) {
            if (llvm::isa<llvm::ConstantData>(val) ||
                    llvm::isa<llvm::ConstantAggregateZero>(val)) {
                return val;
            }

            std::vector<llvm::Constant *> elements;
            if (auto agg = llvm::dyn_cast<llvm::ConstantAggregate>(val)) {
                CloneContents(agg);
            }

            if (auto arr = llvm::dyn_cast<llvm::ConstantArray>(val)) {
                return llvm::ConstantArray::get(arr->getType(), elements);

            } else if (auto vec = llvm::dyn_cast<llvm::ConstantVector>(val)) {
                return llvm::ConstantVector::get(elements);

            } else if (auto obj = llvm::dyn_cast<llvm::ConstantStruct>(val)) {
                return llvm::ConstantStruct::get(obj->getType(), elements);

            } else {
                LOG(FATAL)
                    << "Cannot clone " << remill::LLVMThingToString(val);
                return val;
            }
        }

#endif

        static llvm::Function *DeclareFunctionInModule(llvm::Function *func,
                llvm::Module *dest_module) {
            auto dest_func = dest_module->getFunction(func->getName());
            if (dest_func) {
                return dest_func;
            }

            LOG_IF(FATAL, func->hasLocalLinkage())
                << "Cannot declare internal function " << func->getName().str()
                << " as external in another module";

            dest_func =
                llvm::Function::Create(func->getFunctionType(), func->getLinkage(),
                        func->getName(), dest_module);

            dest_func->copyAttributesFrom(func);
            dest_func->setVisibility(func->getVisibility());

            return dest_func;
        }

        static llvm::GlobalVariable *DeclareVarInModule(llvm::GlobalVariable *var,
                llvm::Module *dest_module);

        template <typename T>
            static void ClearMetaData(T *value) {
                llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> mds;
                value->getAllMetadata(mds);
                for (auto md_info : mds) {
                    value->setMetadata(md_info.first, nullptr);
                }
            }

        static llvm::Constant *MoveConstantIntoModule(llvm::Constant *c,
                llvm::Module *dest_module) {

            auto &dest_context = dest_module->getContext();
            auto type = c->getType();
            auto in_same_context = true;
            if (&(c->getContext()) != &dest_context) {
                in_same_context = false;
                type = ::remill::RecontextualizeType(type, dest_context);
            } else {
#if LLVM_VERSION_NUMBER > LLVM_VERSION(3, 8)
                if (!c->needsRelocation()) {
                    return c;
                }
#endif
            }

            if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(c); gv) {
                return DeclareVarInModule(gv, dest_module);

            } else if (auto func = llvm::dyn_cast<llvm::Function>(c); func) {
                return DeclareFunctionInModule(func, dest_module);

            } else if (auto d = llvm::dyn_cast<llvm::ConstantData>(c)) {
                if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(d); ci) {
                    if (in_same_context) {
                        return ci;
                    } else {
                        return llvm::ConstantInt::get(type, ci->getValue());
                    }
                } else if (auto cf = llvm::dyn_cast<llvm::ConstantFP>(d); cf) {
                    if (in_same_context) {
                        return cf;
                    } else {
                        return llvm::ConstantFP::get(type, cf->getValueAPF().convertToDouble());
                    }
                } else if (auto u = llvm::dyn_cast<llvm::UndefValue>(d); u) {
                    if (in_same_context) {
                        return u;
                    } else {
                        return llvm::UndefValue::get(type);
                    }
                } else if (auto p = llvm::dyn_cast<llvm::ConstantPointerNull>(d); p) {
                    if (in_same_context) {
                        return p;
                    } else {
                        return llvm::ConstantPointerNull::get(
                                llvm::cast<llvm::PointerType>(type));
                    }
                } else if (auto z = llvm::dyn_cast<llvm::ConstantAggregateZero>(d); z) {
                    if (in_same_context) {
                        return z;
                    } else {
                        return llvm::ConstantAggregateZero::get(type);
                    }
                } else if (auto a = llvm::dyn_cast<llvm::ConstantDataArray>(d); a) {
                    if (in_same_context) {
                        return a;
                    } else {
                        const auto raw_data = a->getRawDataValues();
                        const auto el_type = a->getElementType();
                        if (el_type->isIntegerTy()) {
                            switch (a->getElementByteSize()) {
                                case 1:
                                    return llvm::ConstantDataArray::get(
                                            dest_context, llvm::arrayRefFromStringRef(raw_data));
                                case 2: {
                                            llvm::ArrayRef<uint16_t> ref(
                                                    reinterpret_cast<const uint16_t *>(raw_data.bytes_begin()),
                                                    reinterpret_cast<const uint16_t *>(raw_data.bytes_end()));
                                            return llvm::ConstantDataArray::get(dest_context, ref);
                                        }
                                case 4: {
                                            llvm::ArrayRef<uint32_t> ref(
                                                    reinterpret_cast<const uint32_t *>(raw_data.bytes_begin()),
                                                    reinterpret_cast<const uint32_t *>(raw_data.bytes_end()));
                                            return llvm::ConstantDataArray::get(dest_context, ref);
                                        }
                                case 8: {
                                            llvm::ArrayRef<uint64_t> ref(
                                                    reinterpret_cast<const uint64_t *>(raw_data.bytes_begin()),
                                                    reinterpret_cast<const uint64_t *>(raw_data.bytes_end()));
                                            return llvm::ConstantDataArray::get(dest_context, ref);
                                        }
                            }
                        } else if (el_type->isFloatTy()) {
                            llvm::ArrayRef<float> ref(
                                    reinterpret_cast<const float *>(raw_data.bytes_begin()),
                                    reinterpret_cast<const float *>(raw_data.bytes_end()));
                            return llvm::ConstantDataArray::get(dest_context, ref);

                        } else if (el_type->isDoubleTy()) {
                            llvm::ArrayRef<double> ref(
                                    reinterpret_cast<const double *>(raw_data.bytes_begin()),
                                    reinterpret_cast<const double *>(raw_data.bytes_end()));
                            return llvm::ConstantDataArray::get(dest_context, ref);
                        }

                        LOG(FATAL) << "Unsupported element type in constant data array: "
                            << remill::LLVMThingToString(el_type);
                        return nullptr;
                    }
                } else if (auto v = llvm::dyn_cast<llvm::ConstantDataVector>(d); v) {
                    if (in_same_context) {
                        return v;
                    } else {
                        LOG(FATAL)
                            << "Moving constant data vectors across contexts is not yet supported";
                        return nullptr;
                    }

                } else if (in_same_context) {
                    LOG(ERROR) << "Not adapting constant when moving to destination module: "
                        << LLVMThingToString(c);
                    return c;

                } else {
                    LOG(FATAL) << "Cannot move constant to destination context: "
                        << LLVMThingToString(c);
                    return nullptr;
                }
            } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(c)) {
                switch (ce->getOpcode()) {
                    case llvm::Instruction::Add: {
                                                     const auto b = llvm::dyn_cast<llvm::AddOperator>(ce);
                                                     return llvm::ConstantExpr::getAdd(
                                                             MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                             MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                             b->hasNoUnsignedWrap(), b->hasNoSignedWrap());
                                                 }
                    case llvm::Instruction::Sub: {
                                                     const auto b = llvm::dyn_cast<llvm::SubOperator>(ce);
                                                     return llvm::ConstantExpr::getSub(
                                                             MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                             MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                             b->hasNoUnsignedWrap(), b->hasNoSignedWrap());
                                                 }
                    case llvm::Instruction::And:
                                                 return llvm::ConstantExpr::getAnd(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::Or:
                                                 return llvm::ConstantExpr::getOr(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::Xor:
                                                 return llvm::ConstantExpr::getXor(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::ICmp:
                                                 return llvm::ConstantExpr::getICmp(
                                                         ce->getPredicate(),
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::ZExt:
                                                 return llvm::ConstantExpr::getZExt(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::SExt:
                                                 return llvm::ConstantExpr::getSExt(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::Trunc:
                                                 return llvm::ConstantExpr::getTrunc(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::Select:
                                                 return llvm::ConstantExpr::getSelect(
                                                         MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                         MoveConstantIntoModule(ce->getOperand(2), dest_module));
                    case llvm::Instruction::Shl: {
                                                     const auto b = llvm::dyn_cast<llvm::ShlOperator>(ce);
                                                     return llvm::ConstantExpr::getShl(
                                                             MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                             MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                             b->hasNoUnsignedWrap(), b->hasNoSignedWrap());
                                                 }
                    case llvm::Instruction::LShr: {
                                                      const auto b = llvm::dyn_cast<llvm::LShrOperator>(ce);
                                                      return llvm::ConstantExpr::getLShr(
                                                              MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                              MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                              b->isExact());
                                                  }
                    case llvm::Instruction::AShr: {
                                                      const auto b = llvm::dyn_cast<llvm::AShrOperator>(ce);
                                                      return llvm::ConstantExpr::getAShr(
                                                              MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                              MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                              b->isExact());
                                                  }
                    case llvm::Instruction::UDiv: {
                                                      const auto b = llvm::dyn_cast<llvm::UDivOperator>(ce);
                                                      return llvm::ConstantExpr::getUDiv(
                                                              MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                              MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                              b->isExact());
                                                  }
                    case llvm::Instruction::SDiv: {
                                                      const auto b = llvm::dyn_cast<llvm::SDivOperator>(ce);
                                                      return llvm::ConstantExpr::getSDiv(
                                                              MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                              MoveConstantIntoModule(ce->getOperand(1), dest_module),
                                                              b->isExact());
                                                  }
                    case llvm::Instruction::URem:
                                                  return llvm::ConstantExpr::getURem(
                                                          MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                          MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::SRem:
                                                  return llvm::ConstantExpr::getSRem(
                                                          MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                          MoveConstantIntoModule(ce->getOperand(1), dest_module));
                    case llvm::Instruction::IntToPtr:
                                                  return llvm::ConstantExpr::getIntToPtr(
                                                          MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::PtrToInt:
                                                  return llvm::ConstantExpr::getPtrToInt(
                                                          MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::BitCast:
                                                  return llvm::ConstantExpr::getBitCast(
                                                          MoveConstantIntoModule(ce->getOperand(0), dest_module), type);
                    case llvm::Instruction::GetElementPtr: {
                                                               const auto g = llvm::dyn_cast<llvm::GEPOperator>(ce);
                                                               const auto ni = g->getNumIndices();
                                                               const auto source_type = ::remill::RecontextualizeType(
                                                                       g->getSourceElementType(), dest_context);
                                                               std::vector<llvm::Constant *> indices(ni);
                                                               for (auto i = 0u; i < ni; ++i) {
                                                                   indices[i] =
                                                                       MoveConstantIntoModule(ce->getOperand(i + 1u), dest_module);
                                                               }
                                                               return llvm::ConstantExpr::getGetElementPtr(
                                                                       source_type, MoveConstantIntoModule(ce->getOperand(0), dest_module),
                                                                       indices, g->isInBounds(), g->getInRangeIndex());
                                                           }
                    default:
                                                           if (in_same_context) {
                                                               LOG(ERROR) << "Unsupported CE when moving across module boundaries: "
                                                                   << LLVMThingToString(ce);
                                                               return ce;

                                                           } else {
                                                               LOG(FATAL) << "Unsupported CE when moving across context boundaries: "
                                                                   << LLVMThingToString(ce);
                                                               return nullptr;
                                                           }
                }
            } else if (auto ca = llvm::dyn_cast<llvm::ConstantAggregate>(c); ca) {
                if (auto a = llvm::dyn_cast<llvm::ConstantArray>(ca); a) {
                    std::vector<llvm::Constant *> new_elems;
                    new_elems.reserve(a->getNumOperands());
                    for (auto it = a->op_begin(), end = a->op_end(); it != end; ++it) {
                        new_elems.push_back(MoveConstantIntoModule(
                                    llvm::cast<llvm::Constant>(it->get()), dest_module));
                    }

                    return llvm::ConstantArray::get(llvm::cast<llvm::ArrayType>(type),
                            new_elems);

                } else if (auto s = llvm::dyn_cast<llvm::ConstantStruct>(ca); s) {
                    std::vector<llvm::Constant *> new_elems;
                    new_elems.reserve(s->getNumOperands());
                    for (auto it = s->op_begin(), end = s->op_end(); it != end; ++it) {
                        new_elems.push_back(MoveConstantIntoModule(
                                    llvm::cast<llvm::Constant>(it->get()), dest_module));
                    }

                    return llvm::ConstantStruct::get(llvm::cast<llvm::StructType>(type),
                            new_elems);

                } else if (auto v = llvm::dyn_cast<llvm::ConstantVector>(ca); v) {
                    std::vector<llvm::Constant *> new_elems;
                    new_elems.reserve(v->getNumOperands());
                    for (auto it = v->op_begin(), end = v->op_end(); it != end; ++it) {
                        new_elems.push_back(MoveConstantIntoModule(
                                    llvm::cast<llvm::Constant>(it->get()), dest_module));
                    }

                    return llvm::ConstantVector::get(new_elems);

                } else if (in_same_context) {
                    LOG(ERROR) << "Unsupported CA when moving across module boundaries: "
                        << LLVMThingToString(ce);
                    return ca;

                } else {
                    LOG(FATAL) << "Unsupported CA when moving across context boundaries: "
                        << LLVMThingToString(ce);
                    return nullptr;
                }

            } else if (in_same_context) {
                LOG(ERROR) << "Unsupported constant when moving across module boundaries: "
                    << LLVMThingToString(ce);
                return c;

            } else {
                LOG(FATAL) << "Unsupported constant when moving across context boundaries: "
                    << LLVMThingToString(ce);
                return nullptr;
            }
        }

        llvm::GlobalVariable *DeclareVarInModule(llvm::GlobalVariable *var,
                llvm::Module *dest_module) {
            auto dest_var = dest_module->getGlobalVariable(var->getName());
            if (dest_var) {
                return dest_var;
            }

            auto type = var->getType()->getElementType();
            dest_var = new llvm::GlobalVariable(
                    *dest_module, type, var->isConstant(), var->getLinkage(), nullptr,
                    var->getName(), nullptr, var->getThreadLocalMode(),
                    var->getType()->getAddressSpace());

            dest_var->copyAttributesFrom(var);

            if (var->hasInitializer() && var->hasLocalLinkage()) {
                auto initializer = var->getInitializer();
                dest_var->setInitializer(MoveConstantIntoModule(initializer, dest_module));
            } else {
                LOG_IF(FATAL, var->hasLocalLinkage())
                    << "Cannot declare internal variable " << var->getName().str()
                    << " as external in another module";
            }

            return dest_var;
        }

    }  // namespace

    // Clone function `source_func` into `dest_func`, using `value_map` to map over
    // values. This will strip out debug info during the clone. This will strip out
    // debug info during the clone.
    //
    // Note: this will try to clone globals referenced from the module of
    //       `source_func` into the module of `dest_func`.
    void CloneFunctionInto(llvm::Function *source_func, llvm::Function *dest_func,
            ValueMap &value_map) {

        auto func_name = source_func->getName().str();
        auto source_mod = source_func->getParent();
        auto dest_mod = dest_func->getParent();
        auto &source_context = source_mod->getContext();
        auto &dest_context = dest_func->getContext();
        auto reg_md_id = source_context.getMDKindID("remill_register");

        // Make sure that when we're cloning `__remill_basic_block`, we don't
        // throw away register names and such.
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 9)
        dest_func->getContext().setDiscardValueNames(false);
#endif

        dest_func->setAttributes(source_func->getAttributes());
        dest_func->setLinkage(source_func->getLinkage());
        dest_func->setVisibility(source_func->getVisibility());
        dest_func->setCallingConv(source_func->getCallingConv());

#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
        dest_func->setIsMaterializable(source_func->isMaterializable());
#endif

        // Clone the basic blocks and their instructions.
        std::unordered_map<llvm::BasicBlock *, llvm::BasicBlock *> block_map;
        for (auto &old_block : *source_func) {
            auto new_block = llvm::BasicBlock::Create(dest_func->getContext(),
                    old_block.getName(), dest_func);
            value_map[&old_block] = new_block;
            block_map[&old_block] = new_block;

            auto &new_insts = new_block->getInstList();
            for (auto &old_inst : old_block) {
                if (llvm::isa<llvm::DbgInfoIntrinsic>(old_inst)) {
                    continue;
                }

                auto new_inst = old_inst.clone();
                new_insts.push_back(new_inst);
                value_map[&old_inst] = new_inst;
            }
        }

        llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> mds;

        // Fixup the references in the cloned instructions so that they point into
        // the cloned function, or point to declared globals in the module containing
        // `dest_func`.
        for (auto &old_block : *source_func) {
            for (auto &old_inst : old_block) {
                if (llvm::isa<llvm::DbgInfoIntrinsic>(old_inst)) {
                    continue;
                }

                auto new_inst = llvm::dyn_cast<llvm::Instruction>(value_map[&old_inst]);

                // Clear out all metadata from the new instruction.

                old_inst.getAllMetadata(mds);
                for (auto md_info : mds) {
                    if (md_info.first != reg_md_id || &source_context != &dest_context) {
                        new_inst->setMetadata(md_info.first, nullptr);
                    }
                }

                new_inst->setDebugLoc(llvm::DebugLoc());
                new_inst->setName(old_inst.getName());

                for (auto &new_op : new_inst->operands()) {
                    auto old_op_val = new_op.get();

                    if (llvm::isa<llvm::Constant>(old_op_val) &&
                            !llvm::isa<llvm::GlobalValue>(old_op_val)) {
                        continue;  // Don't clone constants.
                    }

                    // Already cloned the value, replace the old with the new.
                    auto new_op_val_it = value_map.find(old_op_val);
                    if (value_map.end() != new_op_val_it) {
                        new_op.set(new_op_val_it->second);
                        continue;
                    }

                    // At this point, all we should have is a global.
                    auto global_val = llvm::dyn_cast<llvm::GlobalValue>(old_op_val);
                    if (!global_val) {
                        LOG(FATAL) << "Cannot clone value " << LLVMThingToString(old_op_val)
                            << " from function " << func_name << " because it isn't "
                            << "a global value.";
                    }

                    // If it's a global and we're in the same module, then use it.
                    if (global_val && dest_mod == source_mod) {
                        value_map[global_val] = global_val;
                        new_op.set(global_val);
                        continue;
                    }

                    // Declare the global in the new module.
                    llvm::GlobalValue *new_global_val = nullptr;

                    if (auto global_val_func = llvm::dyn_cast<llvm::Function>(global_val);
                            global_val_func) {
                        auto new_func = dest_mod->getOrInsertFunction(
                                global_val->getName(),
                                llvm::dyn_cast<llvm::FunctionType>(GetValueType(global_val)));

                        new_global_val = llvm::dyn_cast<llvm::GlobalValue>(
                                new_func IF_LLVM_GTE_900(.getCallee()));

                        if (auto as_func = llvm::dyn_cast<llvm::Function>(new_global_val)) {
                            as_func->setAttributes(global_val_func->getAttributes());
                        }

                    } else if (auto global_val_var =
                            llvm::dyn_cast<llvm::GlobalVariable>(global_val);
                            global_val_var) {
                        const auto new_global_val_var =
                            llvm::dyn_cast<llvm::GlobalVariable>(dest_mod->getOrInsertGlobal(
                                        global_val->getName(), GetValueType(global_val)));
                        if (new_global_val_var != global_val_var &&
                                global_val_var->hasInitializer()) {
                            new_global_val_var->setInitializer(MoveConstantIntoModule(
                                        global_val_var->getInitializer(), dest_mod));
                        }

                        new_global_val = new_global_val_var;

                    } else {
                        LOG(FATAL) << "Cannot clone value " << LLVMThingToString(old_op_val)
                            << " into new module for function " << func_name;
                    }

                    auto old_name = global_val->getName().str();
                    auto new_name = new_global_val->getName().str();

                    CHECK(new_global_val->getName() == global_val->getName())
                        << "Name of cloned global value declaration for " << old_name
                        << "does not match global value definition of " << new_name
                        << " in the source module. The cloned value probably has the "
                        << "same name as another value in the dest module, but with a "
                        << "different type.";

                    // Mark the global as extern, so that it can link back to the old
                    // module.
                    new_global_val->setLinkage(llvm::GlobalValue::ExternalLinkage);
                    new_global_val->setVisibility(llvm::GlobalValue::DefaultVisibility);

                    value_map[global_val] = new_global_val;
                    new_op.set(new_global_val);
                }

                // Remap PHI node predecessor blocks.
                if (auto phi = llvm::dyn_cast<llvm::PHINode>(new_inst)) {
                    for (auto i = 0UL; i < phi->getNumIncomingValues(); ++i) {
                        phi->setIncomingBlock(i, block_map[phi->getIncomingBlock(i)]);
                    }
                }
            }
        }
    }

    // Move a function from one module into another module.
    //
    // TODO(pag): Make this work across distinct `llvm::LLVMContext`s.
    void MoveFunctionIntoModule(llvm::Function *func, llvm::Module *dest_module) {
        const auto source_context = &(func->getContext());
        const auto dest_context = &(dest_module->getContext());
        CHECK(source_context == dest_context)
            << "Cannot move function across two independent LLVM contexts.";

        auto source_module = func->getParent();
        CHECK(source_module != dest_module)
            << "Cannot move function to the same module.";

        auto existing = dest_module->getFunction(func->getName());
        if (existing) {
            CHECK(existing->isDeclaration())
                << "Function " << func->getName().str()
                << " already exists in destination module.";
            existing->setName(llvm::Twine::createNull());
            existing->setLinkage(llvm::GlobalValue::PrivateLinkage);
            existing->setVisibility(llvm::GlobalValue::DefaultVisibility);
        }

        const auto in_same_context = source_context == dest_context;

        if (in_same_context) {
            func->removeFromParent();
            dest_module->getFunctionList().push_back(func);
        }

        if (existing) {
            existing->replaceAllUsesWith(func);
            existing->eraseFromParent();
            existing = nullptr;
        }

        if (!in_same_context) {
            IF_LLVM_GTE_370(ClearMetaData(func);)
        }

        for (auto &block : *func) {
            for (auto &inst : block) {

                if (!in_same_context) {
                    ClearMetaData(&inst);
                }

                // Substitute globals in the operands.
                for (auto &op : inst.operands()) {
                    if (auto c = llvm::dyn_cast<llvm::Constant>(op.get()); c) {
                        op.set(MoveConstantIntoModule(c, dest_module));
                    }
                }
            }
        }
    }

    namespace {

        static llvm::Type *
            RecontextualizeType(llvm::Type *type, llvm::LLVMContext &context,
                    std::unordered_map<llvm::Type *, llvm::Type *> &cache) {
                auto &cached = cache[type];
                if (cached) {
                    return cached;
                }

                switch (type->getTypeID()) {
                    case llvm::Type::VoidTyID: return llvm::Type::getVoidTy(context);
                    case llvm::Type::HalfTyID: return llvm::Type::getHalfTy(context);
                    case llvm::Type::FloatTyID: return llvm::Type::getFloatTy(context);
                    case llvm::Type::DoubleTyID: return llvm::Type::getDoubleTy(context);
                    case llvm::Type::X86_FP80TyID: return llvm::Type::getX86_FP80Ty(context);
                    case llvm::Type::FP128TyID: return llvm::Type::getFP128Ty(context);
                    case llvm::Type::PPC_FP128TyID: return llvm::Type::getPPC_FP128Ty(context);
                    case llvm::Type::LabelTyID: return llvm::Type::getLabelTy(context);
                    case llvm::Type::MetadataTyID: return llvm::Type::getMetadataTy(context);
                    case llvm::Type::X86_MMXTyID: return llvm::Type::getX86_MMXTy(context);
                    case llvm::Type::TokenTyID: return llvm::Type::getTokenTy(context);
                    case llvm::Type::IntegerTyID: {
                                                      auto int_type = llvm::dyn_cast<llvm::IntegerType>(type);
                                                      cached =
                                                          llvm::IntegerType::get(context, int_type->getPrimitiveSizeInBits());
                                                      break;
                                                  }
                    case llvm::Type::FunctionTyID: {
                                                       auto func_type = llvm::dyn_cast<llvm::FunctionType>(type);
                                                       auto ret_type =
                                                           RecontextualizeType(func_type->getReturnType(), context, cache);
                                                       llvm::SmallVector<llvm::Type *, 4> param_types;
                                                       for (auto param_type : func_type->params()) {
                                                           param_types.push_back(RecontextualizeType(param_type, context, cache));
                                                       }
                                                       cached =
                                                           llvm::FunctionType::get(ret_type, param_types, func_type->isVarArg());
                                                       break;
                                                   }

                    case llvm::Type::StructTyID: {
                                                     auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
                                                     auto new_struct_type =
                                                         llvm::StructType::create(context, struct_type->getName());
                                                     cached = new_struct_type;

                                                     llvm::SmallVector<llvm::Type *, 4> elem_types;
                                                     for (auto elem_type : struct_type->elements()) {
                                                         elem_types.push_back(RecontextualizeType(elem_type, context, cache));
                                                     }

                                                     if (elem_types.size()) {
                                                         new_struct_type->setBody(elem_types, struct_type->isPacked());
                                                     }

                                                     return new_struct_type;
                                                 }

                    case llvm::Type::ArrayTyID: {
                                                    auto arr_type = llvm::dyn_cast<llvm::ArrayType>(type);
                                                    auto elem_type = arr_type->getElementType();
                                                    cached =
                                                        llvm::ArrayType::get(RecontextualizeType(elem_type, context, cache),
                                                                arr_type->getNumElements());
                                                    break;
                                                }

                    case llvm::Type::PointerTyID: {
                                                      auto ptr_type = llvm::dyn_cast<llvm::PointerType>(type);
                                                      auto elem_type = ptr_type->getElementType();
                                                      cached =
                                                          llvm::PointerType::get(RecontextualizeType(elem_type, context, cache),
                                                                  ptr_type->getAddressSpace());
                                                      break;
                                                  }

                    case llvm::Type::VectorTyID: {
                                                     auto arr_type = llvm::dyn_cast<llvm::VectorType>(type);
                                                     auto elem_type = arr_type->getElementType();
                                                     cached =
                                                         llvm::VectorType::get(RecontextualizeType(elem_type, context, cache),
                                                                 arr_type->getNumElements());
                                                     break;
                                                 }

                    default:
                                                 LOG(FATAL) << "Unable to recontextualize type "
                                                     << LLVMThingToString(type);
                                                 return nullptr;
                }

                return cached;
            }

    }  // namespace

    // Get an instance of `type` that belongs to `context`.
    llvm::Type *RecontextualizeType(llvm::Type *type, llvm::LLVMContext &context) {
        if (&(type->getContext()) == &context) {
            return type;
        }

        std::unordered_map<llvm::Type *, llvm::Type *> cache;
        return RecontextualizeType(type, context, cache);
    }

    // Produce a sequence of instructions that will load values from
    // memory, building up the correct type. This will invoke the various
    // memory read intrinsics in order to match the right type, or
    // recursively build up the right type.
    llvm::Value *LoadFromMemory(const IntrinsicTable &intrinsics,
            llvm::BasicBlock *block, llvm::Type *type,
            llvm::Value *mem_ptr, llvm::Value *addr) {

        const auto initial_addr = addr;
        auto module = intrinsics.error->getParent();
        auto &context = module->getContext();
        llvm::DataLayout dl(module);
        llvm::Value *args_2[2] = {mem_ptr, addr};
        auto index_type = llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0));

        llvm::IRBuilder<> ir(block);

        switch (type->getTypeID()) {
            case llvm::Type::HalfTyID: {
                                           llvm::Type *types[] = {llvm::Type::getFloatTy(context)};
                                           auto converter = llvm::Intrinsic::getDeclaration(
                                                   module, llvm::Intrinsic::convert_from_fp16, types);
                                           llvm::Value *conv_args[] = {
                                               ir.CreateCall(intrinsics.read_memory_16, args_2)};
                                           return ir.CreateFPTrunc(ir.CreateCall(converter, conv_args), type);
                                       }

            case llvm::Type::FloatTyID:
                                       return ir.CreateCall(intrinsics.read_memory_f32, args_2);

            case llvm::Type::DoubleTyID:
                                       return ir.CreateCall(intrinsics.read_memory_f64, args_2);

            case llvm::Type::X86_FP80TyID:
                                       return ir.CreateFPExt(ir.CreateCall(intrinsics.read_memory_f80, args_2),
                                               type);

            case llvm::Type::X86_MMXTyID:
                                       return ir.CreateBitCast(ir.CreateCall(intrinsics.read_memory_64, args_2),
                                               type);

            case llvm::Type::IntegerTyID:
                                       switch (auto size = dl.getTypeAllocSize(type)) {
                                           case 1: return ir.CreateCall(intrinsics.read_memory_8, args_2);
                                           case 2: return ir.CreateCall(intrinsics.read_memory_16, args_2);
                                           case 4: return ir.CreateCall(intrinsics.read_memory_32, args_2);
                                           case 8: return ir.CreateCall(intrinsics.read_memory_64, args_2);
                                           default: break;
                                       }
                                       [[clang::fallthrough]];

            case llvm::Type::FP128TyID:
            case llvm::Type::PPC_FP128TyID: {
                                                const auto size = dl.getTypeAllocSize(type);
                                                auto res = ir.CreateAlloca(type);
                                                auto i8_type = llvm::Type::getInt8Ty(context);
                                                auto byte_array =
                                                    ir.CreateBitCast(res, llvm::PointerType::get(i8_type, 0));
                                                llvm::Value *gep_indices[2] = {
                                                    llvm::ConstantInt::get(index_type, 0, false), nullptr};

                                                // Load one byte at a time from memory, and store it into
                                                // `res`.
                                                for (auto i = 0U; i < size; ++i) {
                                                    args_2[1] = ir.CreateAdd(
                                                            addr, llvm::ConstantInt::get(addr->getType(), i, false));
                                                    auto byte = ir.CreateCall(intrinsics.read_memory_8, args_2);
                                                    gep_indices[1] = llvm::ConstantInt::get(index_type, i, false);
                                                    auto byte_ptr = ir.CreateInBoundsGEP(type, byte_array, gep_indices);
                                                    ir.CreateStore(byte, byte_ptr);
                                                }

                                                return ir.CreateLoad(res);
                                            }

                                            // Building up a structure requires us to start with an undef value,
                                            // then inject each element value one at a time.
            case llvm::Type::StructTyID: {
                                             const auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
                                             const auto layout = dl.getStructLayout(struct_type);
                                             llvm::Value *val = llvm::UndefValue::get(type);
                                             const auto num_elems = struct_type->getNumElements();
                                             for (auto i = 0u; i < num_elems; ++i) {
                                                 const auto elem_type = struct_type->getStructElementType(i);
                                                 const auto offset = layout->getElementOffset(i);
                                                 addr = ir.CreateAdd(initial_addr, llvm::ConstantInt::get(
                                                             addr->getType(), offset, false));
                                                 auto elem_val =
                                                     LoadFromMemory(intrinsics, block, elem_type, mem_ptr, addr);
                                                 ir.SetInsertPoint(block);
                                                 unsigned indexes[] = {i};
                                                 val = ir.CreateInsertValue(val, elem_val, indexes);
                                             }
                                             return val;
                                         }

                                         // Build up the array in the same was as we do with structures.
            case llvm::Type::ArrayTyID: {
                                            auto arr_type = llvm::dyn_cast<llvm::ArrayType>(type);
                                            const auto num_elems = arr_type->getNumElements();
                                            const auto elem_type = arr_type->getElementType();
                                            const auto elem_size = dl.getTypeAllocSize(elem_type);
                                            llvm::Value *val = llvm::UndefValue::get(type);

                                            for (uint64_t index = 0, offset = 0; index < num_elems;
                                                    ++index, offset += elem_size) {
                                                addr = ir.CreateAdd(initial_addr, llvm::ConstantInt::get(
                                                            addr->getType(), offset, false));
                                                unsigned indexes[] = {static_cast<unsigned>(index)};
                                                auto elem_val =
                                                    LoadFromMemory(intrinsics, block, elem_type, mem_ptr, addr);
                                                ir.SetInsertPoint(block);
                                                val = ir.CreateInsertValue(val, elem_val, indexes);
                                            }
                                            return val;
                                        }

                                        // Read pointers from memory by loading the correct sized integer,
                                        // then casting it to a pointer.
            case llvm::Type::PointerTyID: {
                                              auto ptr_type = llvm::dyn_cast<llvm::PointerType>(type);
                                              auto size_bits = dl.getTypeAllocSizeInBits(ptr_type);
                                              auto intptr_type =
                                                  llvm::IntegerType::get(context, static_cast<unsigned>(size_bits));
                                              auto addr_val =
                                                  LoadFromMemory(intrinsics, block, intptr_type, mem_ptr, addr);
                                              ir.SetInsertPoint(block);
                                              return ir.CreateIntToPtr(addr_val, ptr_type);
                                          }

                                          // Build up the vector in the nearly the same was as we do with arrays.
            case llvm::Type::VectorTyID: {
                                             auto vec_type = llvm::dyn_cast<llvm::VectorType>(type);
                                             const auto num_elems = vec_type->getNumElements();
                                             const auto elem_type = vec_type->getElementType();
                                             const auto elem_size = dl.getTypeAllocSize(elem_type);
                                             llvm::Value *val = llvm::UndefValue::get(type);

                                             for (uint64_t index = 0, offset = 0; index < num_elems;
                                                     ++index, offset += elem_size) {
                                                 addr = ir.CreateAdd(initial_addr, llvm::ConstantInt::get(
                                                             addr->getType(), offset, false));
                                                 auto elem_val =
                                                     LoadFromMemory(intrinsics, block, elem_type, mem_ptr, addr);
                                                 ir.SetInsertPoint(block);
                                                 val =
                                                     ir.CreateInsertElement(val, elem_val, static_cast<unsigned>(index));
                                             }
                                             return val;
                                         }

            case llvm::Type::VoidTyID:
            case llvm::Type::LabelTyID:
            case llvm::Type::MetadataTyID:
            case llvm::Type::TokenTyID:
            case llvm::Type::FunctionTyID:
            default:
                                         LOG(FATAL) << "Unable to produce IR sequence to load type "
                                             << remill::LLVMThingToString(type) << " from memory";
                                         return nullptr;
        }
    }

    // Produce a sequence of instructions that will store a value to
    // memory. This will invoke the various memory write intrinsics
    // in order to match the right type, or recursively destructure
    // the type into components which can be written to memory.
    //
    // Returns the new value of the memory pointer.
    llvm::Value *StoreToMemory(const IntrinsicTable &intrinsics,
            llvm::BasicBlock *block, llvm::Value *val_to_store,
            llvm::Value *mem_ptr, llvm::Value *addr) {

        const auto initial_addr = addr;
        auto module = intrinsics.error->getParent();
        auto &context = module->getContext();
        llvm::DataLayout dl(module);
        llvm::Value *args_3[3] = {mem_ptr, addr, val_to_store};
        auto index_type = llvm::Type::getInt32Ty(context);

        llvm::IRBuilder<> ir(block);

        auto type = val_to_store->getType();
        switch (type->getTypeID()) {
            case llvm::Type::HalfTyID: {
                                           llvm::Type *types[] = {llvm::Type::getFloatTy(context)};
                                           auto converter = llvm::Intrinsic::getDeclaration(
                                                   module, llvm::Intrinsic::convert_to_fp16, types);
                                           llvm::Value *conv_args[] = {
                                               ir.CreateFPExt(val_to_store, llvm::Type::getFloatTy(context))};
                                           args_3[2] = ir.CreateCall(converter, conv_args);

                                           return ir.CreateCall(intrinsics.write_memory_16, args_3);
                                       }

            case llvm::Type::FloatTyID:
                                       return ir.CreateCall(intrinsics.write_memory_f32, args_3);

            case llvm::Type::DoubleTyID:
                                       return ir.CreateCall(intrinsics.write_memory_f64, args_3);

            case llvm::Type::X86_FP80TyID: {
                                               auto double_type = llvm::Type::getDoubleTy(context);
                                               args_3[2] = ir.CreateFPTrunc(val_to_store, double_type);
                                               return ir.CreateCall(intrinsics.write_memory_f80, args_3);
                                           }

            case llvm::Type::X86_MMXTyID: {
                                              auto i64_type = llvm::Type::getInt64Ty(context);
                                              args_3[2] = ir.CreateBitCast(val_to_store, i64_type);
                                              return ir.CreateCall(intrinsics.write_memory_64, args_3);
                                          }

            case llvm::Type::IntegerTyID:
                                          switch (auto size = dl.getTypeAllocSize(type)) {
                                              case 1: return ir.CreateCall(intrinsics.write_memory_8, args_3);
                                              case 2: return ir.CreateCall(intrinsics.write_memory_16, args_3);
                                              case 4: return ir.CreateCall(intrinsics.write_memory_32, args_3);
                                              case 8: return ir.CreateCall(intrinsics.write_memory_64, args_3);
                                              default: break;
                                          }
                                          [[clang::fallthrough]];

            case llvm::Type::FP128TyID:
            case llvm::Type::PPC_FP128TyID: {
                                                const auto size = dl.getTypeAllocSize(type);

                                                // Stack-allocate the value, so we can pull out one byte
                                                // at a time from it, and then write it into the target
                                                // address space.
                                                auto res = ir.CreateAlloca(type);
                                                ir.CreateStore(val_to_store, res);

                                                auto i8_type = llvm::Type::getInt8Ty(context);
                                                auto byte_array =
                                                    ir.CreateBitCast(res, llvm::PointerType::get(i8_type, 0));
                                                llvm::Value *gep_indices[2] = {
                                                    llvm::ConstantInt::get(index_type, 0, false), nullptr};

                                                // Store one byte at a time to memory.
                                                for (auto i = 0U; i < size; ++i) {
                                                    args_3[1] = ir.CreateAdd(
                                                            addr, llvm::ConstantInt::get(addr->getType(), i, false));
                                                    gep_indices[1] = llvm::ConstantInt::get(index_type, i, false);
                                                    auto byte_ptr = ir.CreateInBoundsGEP(type, byte_array, gep_indices);
                                                    args_3[2] = ir.CreateLoad(byte_ptr);
                                                    args_3[0] = ir.CreateCall(intrinsics.write_memory_8, args_3);
                                                }

                                                return args_3[0];
                                            }

                                            // Store a structure by storing the individual elements of the structure.
            case llvm::Type::StructTyID: {
                                             auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
                                             const auto layout = dl.getStructLayout(struct_type);
                                             const auto num_elems = struct_type->getNumElements();
                                             for (auto i = 0u; i < num_elems; ++i) {
                                                 const auto offset = layout->getElementOffset(i);
                                                 const auto elem_addr = ir.CreateAdd(
                                                         initial_addr,
                                                         llvm::ConstantInt::get(addr->getType(), offset, false));
                                                 unsigned indexes[] = {i};
                                                 const auto elem_val = ir.CreateExtractValue(val_to_store, indexes);
                                                 mem_ptr =
                                                     StoreToMemory(intrinsics, block, elem_val, mem_ptr, elem_addr);
                                                 ir.SetInsertPoint(block);
                                             }
                                             return mem_ptr;
                                         }

                                         // Build up the array store in the same was as we do with structures.
            case llvm::Type::ArrayTyID: {
                                            auto arr_type = llvm::dyn_cast<llvm::ArrayType>(type);
                                            const auto num_elems = arr_type->getNumElements();
                                            const auto elem_type = arr_type->getElementType();
                                            const auto elem_size = dl.getTypeAllocSize(elem_type);

                                            for (uint64_t index = 0, offset = 0; index < num_elems;
                                                    ++index, offset += elem_size) {

                                                auto elem_addr = ir.CreateAdd(
                                                        initial_addr,
                                                        llvm::ConstantInt::get(addr->getType(), offset, false));
                                                unsigned indexes[] = {static_cast<unsigned>(index)};
                                                auto elem_val = ir.CreateExtractValue(val_to_store, indexes);
                                                mem_ptr =
                                                    StoreToMemory(intrinsics, block, elem_val, mem_ptr, elem_addr);
                                                ir.SetInsertPoint(block);
                                                offset += elem_size;
                                                index += 1;
                                            }
                                            return mem_ptr;
                                        }

                                        // Write pointers to memory by converting to the correct sized integer,
                                        // then storing that
            case llvm::Type::PointerTyID: {
                                              auto ptr_type = llvm::dyn_cast<llvm::PointerType>(type);
                                              auto size_bits = dl.getTypeAllocSizeInBits(ptr_type);
                                              auto intptr_type =
                                                  llvm::IntegerType::get(context, static_cast<unsigned>(size_bits));
                                              return StoreToMemory(intrinsics, block,
                                                      ir.CreatePtrToInt(val_to_store, intptr_type),
                                                      mem_ptr, addr);
                                          }

                                          // Build up the vector store in the nearly the same was as we do with arrays.
            case llvm::Type::VectorTyID: {
                                             auto vec_type = llvm::dyn_cast<llvm::VectorType>(type);
                                             const auto num_elems = vec_type->getNumElements();
                                             const auto elem_type = vec_type->getElementType();
                                             const auto elem_size = dl.getTypeAllocSize(elem_type);

                                             for (uint64_t index = 0, offset = 0; index < num_elems;
                                                     ++index, offset += elem_size) {

                                                 auto elem_addr = ir.CreateAdd(
                                                         initial_addr,
                                                         llvm::ConstantInt::get(addr->getType(), offset, false));
                                                 auto elem_val =
                                                     ir.CreateExtractElement(val_to_store, static_cast<unsigned>(index));
                                                 mem_ptr =
                                                     StoreToMemory(intrinsics, block, elem_val, mem_ptr, elem_addr);
                                                 ir.SetInsertPoint(block);
                                                 offset += elem_size;
                                                 index += 1;
                                             }

                                             return mem_ptr;
                                         }

            case llvm::Type::VoidTyID:
            case llvm::Type::LabelTyID:
            case llvm::Type::MetadataTyID:
            case llvm::Type::TokenTyID:
            case llvm::Type::FunctionTyID:
            default:
                                         LOG(FATAL) << "Unable to produce IR sequence to store type "
                                             << remill::LLVMThingToString(type) << " to memory";
                                         return nullptr;
        }
    }

    // Create an array of index values to pass to a GetElementPtr instruction
    // that will let us locate a particular register. Returns the final offset
    // into `type` which was reached as the first value in the pair, and the type
    // of what is at that offset in the second value of the pair.
    std::pair<size_t, llvm::Type *>
        BuildIndexes(const llvm::DataLayout &dl, llvm::Type *type, size_t offset,
                const size_t goal_offset,
                llvm::SmallVectorImpl<llvm::Value *> &indexes_out) {

            CHECK_LE(offset, goal_offset);
            CHECK_LE(goal_offset, (offset + dl.getTypeAllocSize(type)));

            size_t index = 0;
            const auto index_type = indexes_out[0]->getType();

            if (const auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
                    struct_type) {

                auto layout = dl.getStructLayout(struct_type);
                auto prev_elem_offset = 0;
                llvm::Type *prev_elem_type = nullptr;

                for (auto i = 0u, max_i = struct_type->getNumElements(); i < max_i; ++i) {
                    auto elem_offset = layout->getElementOffset(i);
                    auto elem_type = struct_type->getStructElementType(i);
                    auto elem_size = dl.getTypeStoreSize(elem_type);

                    // The goal offset comes after this element.
                    if ((offset + elem_offset + elem_size) <= goal_offset) {
                        prev_elem_offset = elem_offset;
                        prev_elem_type = elem_type;
                        continue;

                        // Indexing into the `i`th element.
                    } else if ((offset + elem_offset) <= goal_offset) {
                        indexes_out.push_back(llvm::ConstantInt::get(index_type, i, false));
                        return BuildIndexes(dl, elem_type, offset + elem_offset, goal_offset,
                                indexes_out);

                        // We're indexing into some padding before the current element.
                    } else if (i) {
                        indexes_out.push_back(llvm::ConstantInt::get(index_type, i - 1, false));
                        return {offset + prev_elem_offset, prev_elem_type};

                        // We're indexing into some padding at the beginning of this structure.
                    } else {
                        return {offset, type};
                    }
                }

            } else if (auto seq_type = llvm::dyn_cast<llvm::SequentialType>(type);
                    seq_type) {
                const auto elem_type = seq_type->getElementType();
                const auto elem_size = dl.getTypeAllocSize(elem_type);
                const auto num_elems = seq_type->getNumElements();

                while ((offset + elem_size) <= goal_offset && index < num_elems) {
                    offset += elem_size;
                    index += 1;
                }

                CHECK_LE(offset, goal_offset);
                CHECK_LE(goal_offset, (offset + elem_size));

                indexes_out.push_back(llvm::ConstantInt::get(index_type, index, false));
                return BuildIndexes(dl, elem_type, offset, goal_offset, indexes_out);
            }

            return {offset, type};
        }

    // Given a pointer, `ptr`, and a goal byte offset to which we'd like to index,
    // build either a constant expression or sequence of instructions that can
    // index to that offset. `ir` is provided to support the instruction case
    // and to give access to a module for data layouts.
    llvm::Value *BuildPointerToOffset(llvm::IRBuilder<> &ir, llvm::Value *ptr,
            size_t dest_elem_offset,
            llvm::Type *dest_ptr_type_) {

        const auto block = ir.GetInsertBlock();
        const auto module = block->getModule();
        auto &context = block->getContext();
        const auto i32_type = llvm::Type::getInt32Ty(context);

        const auto &dl = module->getDataLayout();
        llvm::SmallVector<llvm::Value *, 16> indexes;

        auto ptr_type = llvm::dyn_cast<llvm::PointerType>(ptr->getType());
        CHECK_NOTNULL(ptr_type);
        const auto dest_elem_ptr_type =
            llvm::dyn_cast<llvm::PointerType>(dest_ptr_type_);
        CHECK_NOTNULL(dest_elem_ptr_type);
        auto ptr_addr_space = ptr_type->getAddressSpace();
        const auto dest_ptr_addr_space = dest_elem_ptr_type->getAddressSpace();
        auto constant_ptr = llvm::dyn_cast<llvm::Constant>(ptr);

        // Change address spaces if necessary before indexing.
        if (dest_ptr_addr_space != ptr_addr_space) {
            ptr_type = llvm::PointerType::get(ptr_type->getPointerElementType(),
                    dest_ptr_addr_space);
            ptr_addr_space = dest_ptr_addr_space;

            if (constant_ptr) {
                constant_ptr =
                    llvm::ConstantExpr::getAddrSpaceCast(constant_ptr, ptr_type);
                ptr = constant_ptr;
            } else {
                ptr = ir.CreateAddrSpaceCast(ptr, ptr_type);
            }
        }

        const auto dest_elem_type = dest_elem_ptr_type->getElementType();
        const auto ptr_elem_type = ptr_type->getElementType();
        const auto ptr_elem_size = dl.getTypeAllocSize(ptr_elem_type);
        const auto base_index = dest_elem_offset / ptr_elem_size;

        indexes.push_back(llvm::ConstantInt::get(i32_type, base_index, false));

        dest_elem_offset = dest_elem_offset % ptr_elem_size;

        auto [reached_disp, indexed_type] =
            BuildIndexes(dl, ptr_elem_type, 0, dest_elem_offset, indexes);

        if (reached_disp) {
            if (constant_ptr) {
                if (base_index) {
                    constant_ptr = llvm::ConstantExpr::getGetElementPtr(
                            ptr_elem_type, constant_ptr, indexes);
                } else {
                    constant_ptr = llvm::ConstantExpr::getGetElementPtr(
                            ptr_elem_type, constant_ptr, indexes, true,
                            (base_index * ptr_elem_size) + reached_disp);
                }
                ptr = constant_ptr;
            } else {
                if (base_index) {
                    ptr = ir.CreateGEP(ptr_elem_type, ptr, indexes);
                } else {
                    ptr = ir.CreateInBoundsGEP(ptr_elem_type, ptr, indexes);
                }
            }
        }

        if (const auto diff = dest_elem_offset - reached_disp; diff) {
            DCHECK_LT(diff, dest_elem_offset);
            DCHECK_LT(diff, dl.getTypeAllocSize(indexed_type));
            const auto i8_type = llvm::Type::getInt8Ty(context);
            const auto i8_ptr_type =
                llvm::PointerType::getInt8PtrTy(context, ptr_addr_space);

            const auto dest_elem_size = dl.getTypeAllocSize(dest_elem_type);
            if (diff % dest_elem_size) {
                if (constant_ptr) {
                    constant_ptr =
                        llvm::ConstantExpr::getBitCast(constant_ptr, i8_ptr_type);
                    constant_ptr = llvm::ConstantExpr::getGetElementPtr(
                            i8_type, constant_ptr, llvm::ConstantInt::get(i32_type, diff));
                    return llvm::ConstantExpr::getBitCast(constant_ptr, dest_elem_ptr_type);

                } else {
                    ptr = ir.CreateBitCast(ptr, i8_ptr_type);
                    ptr = ir.CreateGEP(i8_type, ptr,
                            llvm::ConstantInt::get(i32_type, diff, false));
                    return ir.CreateBitCast(ptr, dest_elem_ptr_type);
                }
            } else {
                if (constant_ptr) {
                    constant_ptr =
                        llvm::ConstantExpr::getBitCast(constant_ptr, dest_elem_ptr_type);
                    return llvm::ConstantExpr::getGetElementPtr(
                            dest_elem_type, constant_ptr,
                            llvm::ConstantInt::get(i32_type, diff / dest_elem_size));
                } else {
                    ptr = ir.CreateBitCast(ptr, dest_elem_ptr_type);
                    return ir.CreateGEP(
                            dest_elem_type, ptr,
                            llvm::ConstantInt::get(i32_type, diff / dest_elem_size, false));
                }
            }
        }

        if (constant_ptr) {
            return llvm::ConstantExpr::getBitCast(constant_ptr, dest_elem_ptr_type);
        } else {
            return ir.CreateBitCast(ptr, dest_elem_ptr_type);
        }
    }


    // Compute the total offset of a GEP chain.
    std::pair<llvm::Value *, int64_t>
        StripAndAccumulateConstantOffsets(const llvm::DataLayout &dl,
                llvm::Value *base) {
            const auto ptr_size = dl.getPointerSizeInBits(0);
            int64_t total_offset = 0;
            while (base) {
                if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(base); gep) {
                    llvm::APInt accumulated_offset(ptr_size, 0, false);
                    if (!gep->accumulateConstantOffset(dl, accumulated_offset)) {
                        break;
                    }

                    const auto curr_offset = accumulated_offset.getSExtValue();
                    total_offset += curr_offset;

                    base = gep->getPointerOperand();

                } else if (auto bc = llvm::dyn_cast<llvm::BitCastOperator>(base); bc) {
                    base = bc->getOperand(0);

                } else if (auto itp = llvm::dyn_cast<llvm::IntToPtrInst>(base); itp) {
                    base = itp->getOperand(0);

                } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(base); pti) {
                    base = pti->getOperand(0);

                } else {
                    break;
                }
            }
            return {base, total_offset};
        }

}  // namespace remill
