//===-- SpecialFunctionHandler.cpp ----------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "CoreStats.h"
#include "ExternalDispatcher.h"
#include "StatsTracker.h"
#include "glog/logging.h"

#include "SpecialFunctionHandler.h"

#include "Executor.h"
#include "Memory.h"
#include "MemoryManager.h"
#include "TimingSolver.h"
#include "klee/MergeHandler.h"
#include "Searcher.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/Debug.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/OptionCategories.h"
#include "klee/SolverCmdLine.h"
#include "klee/ExprBuilder.h"
#include "PTree.h"

#include "llvm-c/Core.h"
#include "llvm/ADT/Twine.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "llvm/Support/Compiler.h"
#include "llvm/Support/SwapByteOrder.h"

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstring>
#include <limits>
#include <type_traits>

#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

#include "../Native/Arch/X86/Log.cpp"
#include "Native/Memory/AddressSpace.h"
#include "Native/Memory/AllocList.h"
#include "remill/Arch/X86/Runtime/State.h"
#include "remill/BC/Util.h"

#include <fstream>
#include <sstream>
#include <algorithm>

using namespace llvm;
using namespace klee;

namespace {
cl::opt<bool>
    ReadablePosix("readable-posix-inputs", cl::init(false),
                  cl::desc("Prefer creation of POSIX inputs (command-line "
                           "arguments, files, etc.) with human readable bytes. "
                           "Note: option is expensive when creating lots of "
                           "tests (default=false)"));

cl::opt<bool>
    SilentKleeAssume("silent-klee-assume", cl::init(false),
                     cl::desc("Silently terminate paths with an infeasible "
                              "condition given to klee_assume() rather than "
                              "emitting an error (default=false)"));
} // namespace
/// \todo Almost all of the demands in this file should be replaced
/// with terminateState calls.

///

// FIXME: We are more or less committed to requiring an intrinsic
// library these days. We can move some of this stuff there,
// especially things like realloc which have complicated semantics
// w.r.t. forking. Among other things this makes delayed query
// dispatch easier to implement.
static SpecialFunctionHandler::HandlerInfo handlerInfo[] = {
#define add(name, handler, ret)                                                \
  { name, &SpecialFunctionHandler::handler, false, ret, false }
#define addDNR(name, handler)                                                  \
  { name, &SpecialFunctionHandler::handler, true, false, false }
    addDNR("__assert_rtn", handleAssertFail),
    addDNR("__assert_fail", handleAssertFail),
    addDNR("_assert", handleAssert),
    addDNR("abort", handleAbort),
    addDNR("_exit", handleExit),
    {"exit", &SpecialFunctionHandler::handleExit, true, false, true},
    addDNR("klee_abort", handleAbort),
    addDNR("klee_silent_exit", handleSilentExit),
    addDNR("klee_report_error", handleReportError),
    add("calloc", handleCalloc, true),
    add("free", handleFree, false),
    add("klee_assume", handleAssume, false),
    add("klee_check_memory_access", handleCheckMemoryAccess, false),
    add("klee_get_valuef", handleGetValue, true),
    add("klee_get_valued", handleGetValue, true),
    add("klee_get_valuel", handleGetValue, true),
    add("klee_get_valuell", handleGetValue, true),
    add("klee_get_value_i32", handleGetValue, true),
    add("klee_get_value_i64", handleGetValue, true),
    add("klee_define_fixed_object", handleDefineFixedObject, false),
    add("klee_get_obj_size", handleGetObjSize, true),
    add("klee_get_errno", handleGetErrno, true),
#ifndef __APPLE__
    add("__errno_location", handleErrnoLocation, true),

#else
    add("__error", handleErrnoLocation, true),
#endif
    add("klee_is_symbolic", handleIsSymbolic, true),
    add("klee_make_symbolic", handleMakeSymbolic, false),
    add("klee_mark_global", handleMarkGlobal, false),
    add("klee_open_merge", handleOpenMerge, false),
    add("klee_close_merge", handleCloseMerge, false),
    add("klee_prefer_cex", handlePreferCex, false),
    add("klee_posix_prefer_cex", handlePosixPreferCex, false),
    add("klee_print_expr", handlePrintExpr, false),
    add("klee_print_range", handlePrintRange, false),
    add("klee_set_forking", handleSetForking, false),
    add("klee_stack_trace", handleStackTrace, false),
    add("klee_warning", handleWarning, false),
    add("klee_warning_once", handleWarningOnce, false),
    add("klee_alias_function", handleAliasFunction, false),
    add("malloc", handleMalloc, true),
    add("memalign", handleMemalign, true),
    add("realloc", handleRealloc, true),

    // operator delete[](void*)
    add("_ZdaPv", handleDeleteArray, false),
    // operator delete(void*)
    add("_ZdlPv", handleDelete, false),

    // operator new[](unsigned int)
    add("_Znaj", handleNewArray, true),
    // operator new(unsigned int)
    add("_Znwj", handleNew, true),

    // FIXME-64: This is wrong for 64-bit long...

    // operator new[](unsigned long)
    add("_Znam", handleNewArray, true),
    // operator new(unsigned long)
    add("_Znwm", handleNew, true),

    // Run clang with -fsanitize=signed-integer-overflow and/or
    // -fsanitize=unsigned-integer-overflow
    add("__ubsan_handle_add_overflow", handleAddOverflow, false),
    add("__ubsan_handle_sub_overflow", handleSubOverflow, false),
    add("__ubsan_handle_mul_overflow", handleMulOverflow, false),
    add("__ubsan_handle_divrem_overflow", handleDivRemOverflow, false),

    // __remill function handling implementations

    add("__kleemill_get_lifted_function", handle__kleemill_get_lifted_function,
        true),
    add("__kleemill_can_write_byte", handle__kleemill_can_write_byte, true),
    add("__kleemill_can_read_byte", handle__kleemill_can_read_byte, true),
    add("__kleemill_free_memory", handle__kleemill_free_memory, true),
    add("__kleemill_allocate_memory", handle__kleemill_allocate_memory, true),
    add("__kleemill_protect_memory", handle__kleemill_protect_memory, true),
    add("__kleemill_is_mapped_address", handle__kleemill_is_mapped_address,
        true),
    add("__kleemill_find_unmapped_address",
        handle__kleemill_find_unmapped_address, true),
    add("__kleemill_log_state", handle__kleemill_log_state, false),

    add("__remill_write_memory_64", handle__remill_write_64, true),
    add("__remill_write_memory_32", handle__remill_write_32, true),
    add("__remill_write_memory_16", handle__remill_write_16, true),
    add("__remill_write_memory_8", handle__remill_write_8, true),
   
    add("__remill_read_memory_64", handle__remill_read_64, true),
    add("__remill_read_memory_32", handle__remill_read_32, true),
    add("__remill_read_memory_16", handle__remill_read_16, true),
    add("__remill_read_memory_8", handle__remill_read_8, true),
    
    add("llvm.ctpop.i32", handle__llvm_ctpop, true),
    add("klee_overshift_check", handle__klee_overshift_check, false),
    add("__kleemill_fstat", handle__fstat64, true),
    add("__kleemill_lstat", handle__lstat64, true),
    add("__kleemill_stat", handle__stat64, true),
    add("__kleemill_stat_val", handle_get_fstat_index, true),
    add("stat64", handle__stat64, true),
    add("my_openat", handle_openat64, true),
    add("__kleemill_readdir_val", handle_get_dirent_index, true),
    add("__kleemill_readdir_name", handle_get_dirent_name, true),
    add("__kleemill_readdir", handle__my_readdir, true),
    add("klee_init_remill_memory", handle_klee_init_remill_mem, false),

    /* libc intercepts*/
    add("symbolic_stdin", handle__symbolic_stdin, true),
    
    add("strtol_intercept", handle__intercept_strtol, true),
    add("malloc_intercept", handle__intercept_malloc, true),
    add("free_intercept", handle__intercept_free, true),
	  add("calloc_intercept", handle__intercept_calloc, true),
	  add("realloc_intercept", handle__intercept_realloc, true),
	  add("malloc_size", handle_malloc_size, true),
//    add("independent_calloc", handle_independent_calloc, true),
//	  add("independent_comalloc", handle_independent_comalloc, true)
	  add("memset_intercept", handle_memset_intercept, true),
	  add("memcpy_intercept" , handle_memcpy_intercept, true),
	  add("memmove_intercept", handle_memmove_intercept, true),
	  add("strcpy_intercept", handle_strcpy_intercept, true),
	  add("strncpy_intercept", handle_strncpy_intercept, true),
	  add("strlen_intercept", handle_strlen_intercept, true),
    add("strnlen_intercept", handle_strnlen_intercept, true),

#undef addDNR
#undef add
};

void SpecialFunctionHandler::handle_memset_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto dest = executor.toUnique(state, arguments[1]);
  auto constant = executor.toUnique(state, arguments[2]);
  auto n = executor.toUnique(state, arguments[3]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto dest_uint = dyn_cast<ConstantExpr>(dest)->getZExtValue();
  auto c_uint = dyn_cast<ConstantExpr>(constant)->getZExtValue();
  auto n_uint = dyn_cast<ConstantExpr>(n)->getZExtValue();
 
  auto mem = executor.Memory(state, mem_uint);

  executor.bindLocal(target, state, dest);

  for (size_t i=0; i < n_uint; ++i) {
    if (!mem->TryWrite(dest_uint + i, static_cast<uint8_t>(c_uint), executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot write to " << std::hex << (dest_uint + i) << std::dec
          << " during memset";
      executor.terminateStateOnError(
          state, "Failed write in memset" , Executor::Assert);
      return;
    }
  }
}

void SpecialFunctionHandler::handle_memcpy_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto dest = executor.toUnique(state, arguments[1]);
  auto src = executor.toUnique(state, arguments[2]);
  auto n = executor.toUnique(state, arguments[3]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto dest_uint = dyn_cast<ConstantExpr>(dest)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();
  auto n_uint = dyn_cast<ConstantExpr>(n)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);

  executor.bindLocal(target, state, dest);

  for (size_t i = 0; i < n_uint; ++i) {
    uint8_t val = 0;

    if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot read from " << std::hex << (src_uint + i) << std::dec
          << " during memcpy";
      executor.terminateStateOnError(
          state, "Failed read in memcpy" , Executor::Assert);
      return;

    } else if (!mem->TryWrite(dest_uint+i, val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot write to " << std::hex << (dest_uint + i)
          << std::dec << " during memcpy";
      executor.terminateStateOnError(
          state, "Failed write in memcpy" , Executor::Assert);
      return;

    // copy symbol from src_uint + i to dest_uint + i
    } else if (val == klee::native::kSymbolicByte) {
      mem->symbolic_memory[dest_uint + i] = mem->symbolic_memory[src_uint + i];

    // erase symbolic val at dest_uint+i, if it exists.
    } else {
      mem->symbolic_memory.erase(dest_uint + i);
    }
  }
}

void SpecialFunctionHandler::handle_memmove_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto dest = executor.toUnique(state, arguments[1]); 
  auto src = executor.toUnique(state, arguments[2]);
  auto n = executor.toUnique(state, arguments[3]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto dest_uint = dyn_cast<ConstantExpr>(dest)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();
  auto n_uint = dyn_cast<ConstantExpr>(n)->getZExtValue();

  uint64_t error_addr = 0;

  executor.bindLocal(target, state, dest);

  auto mem = executor.Memory(state, mem_uint);
  if (dest_uint < src_uint) {
    for (size_t i = 0; i < n_uint; ++i) {
      uint8_t val = 0;

      if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
        error_addr = src_uint + i;
        goto report_read_error;

      } else if (!mem->TryWrite(dest_uint + i, val, executor.policy_handler.get())) {
        error_addr = dest_uint + i;
        goto report_write_error;

      // copy symbol from src_uint + i to dest_uint + i
      } else if (val == klee::native::kSymbolicByte) {
        mem->symbolic_memory[dest_uint + i] = mem->symbolic_memory[src_uint + i];

      // erase symbolic val at dest_uint+i, if it exists.
      } else {
        mem->symbolic_memory.erase(dest_uint + i);
      }
    }
  } else {
    auto src_end = src_uint + n_uint;
    auto dest_end = dest_uint + n_uint;
    for (size_t i = 1; i <= n_uint; ++i) {
      uint8_t val;
      if (!mem->TryRead(src_end - i, &val, executor.policy_handler.get())) {
        error_addr = src_end - i;
        goto report_read_error;

      } else if (!mem->TryWrite(dest_end - i, val, executor.policy_handler.get())) {
        error_addr = dest_end - i;
        goto report_write_error;

      // copy symbol from src_uint + i to dest_uint + i
      } else if (val == klee::native::kSymbolicByte ) {
        mem->symbolic_memory[dest_end - i] = mem->symbolic_memory[src_end - i];

      // erase symbolic val at dest_uint+i, if it exists.
      } else {
        mem->symbolic_memory.erase(dest_end - i);
      }
    }
  }

  return;

report_read_error:
  LOG(ERROR)
      << "Cannot read from " << std::hex << error_addr << std::dec
      << " during memmove";
  executor.terminateStateOnError(
      state, "Failed read in memmove" , Executor::Assert);
  return;

report_write_error:
  LOG(ERROR)
      << "Cannot write to " << std::hex << error_addr << std::dec
      << " during memmove";
  executor.terminateStateOnError(
      state, "Failed write in memmove" , Executor::Assert);
  return;
}

void SpecialFunctionHandler::handle_strncpy_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto dest = executor.toUnique(state, arguments[1]);
  auto src = executor.toUnique(state, arguments[2]);
  auto n = executor.toUnique(state, arguments[3]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto dest_uint = dyn_cast<ConstantExpr>(dest)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();
  auto n_uint = dyn_cast<ConstantExpr>(n)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);
  executor.bindLocal(target, state, dest);

  uint8_t val = 0;
  auto zero = ConstantExpr::create(0,8);

  for (size_t i = 0; i < n_uint; ++i) {
    if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot read from " << std::hex << (src_uint + i) << std::dec
          << " during strncpy";
      executor.terminateStateOnError(
          state, "Failed read in strncpy" , Executor::Assert);
      return;

    } else if (!mem->TryWrite(dest_uint + i, val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot write to " << std::hex << (dest_uint + i) << std::dec
          << " during strncpy";
      executor.terminateStateOnError(
          state, "Failed write in strncpy" , Executor::Assert);
      return;

    } else if (val == klee::native::kSymbolicByte) {
      auto sym_pair = mem->symbolic_memory.find(src_uint + i);
      if (sym_pair != mem->symbolic_memory.end()) {
        auto sym_val = sym_pair->second;
        auto sym_val_eq_zero = EqExpr::create(sym_val, zero);
        bool res = false;
        if (executor.solver->mayBeTrue(state, sym_val_eq_zero, res) && res) {
          executor.addConstraint(state, sym_val_eq_zero);
          val = 0;

          // Opportunistically zero out that byte.
          if (mem->TryWrite(src_uint + i, val, executor.policy_handler.get())) {
            mem->symbolic_memory.erase(src_uint + i);

          // Unable to opportunistically write out zero; then force the symbolic
          // memory to hold a concrete zero.
          } else {
            mem->symbolic_memory[src_uint + i] = zero;
          }

          mem->symbolic_memory.erase(dest_uint + i);
          mem->TryWrite(dest_uint + i, val, executor.policy_handler.get());
        }
      }

    } else {
      mem->symbolic_memory.erase(dest_uint + i);
    }

    if (!val) {
      break;
    }
  }

  for (size_t i = 0; i < n_uint; ++i) {
    if (!mem->TryWrite(dest_uint + i, val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot write trailing zero byte to "
          << std::hex << (dest_uint + i) << std::dec
          << " during strncpy";
      executor.terminateStateOnError(
          state, "Failed write trailing zero in strncpy" , Executor::Assert);
      return;
    }
  }
}

void SpecialFunctionHandler::handle_strlen_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto src = executor.toUnique(state, arguments[1]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);

  uint8_t val = 0;
  size_t i = 0;
  auto zero = ConstantExpr::create(0,8);

  for (; ; ++i) {
    if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot read from " << std::hex << (src_uint + i) << std::dec
          << " during strlen";
      executor.terminateStateOnError(
          state, "Failed read in strlen" , Executor::Assert);
      return;
    }

    if (val == klee::native::kSymbolicByte) {
      auto sym_pair = mem->symbolic_memory.find(src_uint + i);
      if (sym_pair != mem->symbolic_memory.end()) {
        auto sym_val = sym_pair->second;
        auto sym_val_eq_zero = EqExpr::create(sym_val, zero);
        bool res = false;
        if (executor.solver->mayBeTrue(state, sym_val_eq_zero, res) && res) {
          executor.addConstraint(state, sym_val_eq_zero);

          val = 0;

          // Opportunistically zero out that byte.
          if (mem->TryWrite(src_uint + i, val, executor.policy_handler.get())) {
            mem->symbolic_memory.erase(src_uint + i);

          // Unable to opportunistically write out zero; then force the symbolic
          // memory to hold a concrete zero.
          } else {
            mem->symbolic_memory[src_uint + i] = zero;
          }
        }
      }
    }

    if (val == 0) {
      break;
    }
  }
  //  TODO(sai) add some sort of continuation that makes symbolic strlen better

  executor.bindLocal(target, state, ConstantExpr::create(i, 64));
}


void SpecialFunctionHandler::handle_strnlen_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto src = executor.toUnique(state, arguments[1]);
  auto n = executor.toUnique(state, arguments[2]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();
  auto n_uint = dyn_cast<ConstantExpr>(n)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);

  uint8_t val = 0;
  size_t i = 0;
  auto zero = ConstantExpr::create(0,8);

  for (; i < n_uint; ++i) {
    if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot read from " << std::hex << (src_uint + i) << std::dec
          << " during strnlen";
      executor.terminateStateOnError(
          state, "Failed read in strlen" , Executor::Assert);
      return;
    }

    if (val == klee::native::kSymbolicByte) {
      auto sym_pair = mem->symbolic_memory.find(src_uint + i);
      if (sym_pair != mem->symbolic_memory.end()) {
        auto sym_val = sym_pair->second;
        auto sym_val_eq_zero = EqExpr::create(sym_val, zero);
        bool res = false;
        if (executor.solver->mayBeTrue(state, sym_val_eq_zero, res) && res) {
          executor.addConstraint(state, sym_val_eq_zero);

          val = 0;

          // Opportunistically zero out that byte.
          if (mem->TryWrite(src_uint + i, val, executor.policy_handler.get())) {
            mem->symbolic_memory.erase(src_uint + i);

          // Unable to opportunistically write out zero; then force the symbolic
          // memory to hold a concrete zero.
          } else {
            mem->symbolic_memory[src_uint + i] = zero;
          }
        }
      }
    }

    if (val == 0) {
      break;
    }
  }
  //  TODO(sai) add some sort of continuation that makes symbolic strlen better

  executor.bindLocal(target, state, ConstantExpr::create(i, 64));
}

void SpecialFunctionHandler::handle_strcpy_intercept(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_ptr = executor.toUnique(state, arguments[0]);
  auto dest = executor.toUnique(state, arguments[1]);
  auto src = executor.toUnique(state, arguments[2]);

  auto mem_uint = dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
  auto dest_uint = dyn_cast<ConstantExpr>(dest)->getZExtValue();
  auto src_uint = dyn_cast<ConstantExpr>(src)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);
  executor.bindLocal(target, state, dest);

  uint8_t val = 0;
  auto zero = ConstantExpr::create(0,8);

  for (size_t i = 0; ; ++i) {
    if (!mem->TryRead(src_uint + i, &val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot read from " << std::hex << (src_uint + i) << std::dec
          << " during strncpy";
      executor.terminateStateOnError(
          state, "Failed read in strcpy" , Executor::Assert);
      return;

    } else if (!mem->TryWrite(dest_uint + i, val, executor.policy_handler.get())) {
      LOG(ERROR)
          << "Cannot write to " << std::hex << (dest_uint + i) << std::dec
          << " during strcpy";
      executor.terminateStateOnError(
          state, "Failed write in strcpy" , Executor::Assert);
      return;

    } else if (val == klee::native::kSymbolicByte ) {
      auto sym_pair = mem->symbolic_memory.find(src_uint + i);
      if (sym_pair != mem->symbolic_memory.end()) {
        auto sym_val = sym_pair->second;
        auto sym_val_eq_zero = EqExpr::create(sym_val, zero);
        bool res = false;
        if (executor.solver->mayBeTrue(state, sym_val_eq_zero, res) && res) {
          executor.addConstraint(state, sym_val_eq_zero);
          val = 0;

          // Opportunistically zero out that byte.
          if (mem->TryWrite(src_uint + i, val, executor.policy_handler.get())) {
            mem->symbolic_memory.erase(src_uint + i);

          // Unable to opportunistically write out zero; then force the symbolic
          // memory to hold a concrete zero.
          } else {
            mem->symbolic_memory[src_uint + i] = zero;
          }

          mem->symbolic_memory.erase(dest_uint + i);
          mem->TryWrite(dest_uint + i, val, executor.policy_handler.get());
        }
      }

    } else {
      mem->symbolic_memory.erase(dest_uint + i);
    }

    if (!val) {
      break;
    }
  }
}

void SpecialFunctionHandler::handle_malloc_size(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  auto addr_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[1]))->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);
  klee::native::Address address = {};
  address.flat = addr_uint;

  if (address.must_be_0x1 == 0x1 && address.must_be_0xa == 0xa) {
    executor.bindLocal(target, state, ConstantExpr::create(address.size, 64));

  } else {
    LOG(ERROR)
        << "Can't determine size of address=" << std::hex << addr_uint << std::dec;
    executor.bindLocal(target, state, ConstantExpr::create(0, 64));
  }
}

void SpecialFunctionHandler::handle__intercept_realloc(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  auto ptr_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[1]))->getZExtValue();
  auto size = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[2]))->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);
  uint64_t addr = mem->TryRealloc(ptr_uint, size, executor.policy_handler.get());
  executor.bindLocal(target, state, ConstantExpr::create(addr, 64));
}

void SpecialFunctionHandler::handle__intercept_calloc(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  auto size = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[1]))->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);
  auto addr = mem->TryMalloc(size, executor.policy_handler.get());
  if (0 < static_cast<int64_t>(addr)) {
    uint8_t zero = 0;
    for (size_t i = 0; i < size; ++i){
      (void) mem->TryWrite(addr+i, zero, executor.policy_handler.get());
    }
  }
  executor.bindLocal(target, state, ConstantExpr::create(addr, 64));
}

void SpecialFunctionHandler::handle__intercept_strtol(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
//
//  auto nptr_val = executor.toUnique(state, arguments[0]);
//  auto end_ptr_val = executor.toUnique(state, arguments[1]);
//  auto base_val = executor.toUnique(state, arguments[2]);
//
//  auto nptr = dyn_cast<ConstantExpr>(nptr_val)->getZExtValue();
//  ref<Expr> read_byte;
//  int size = 0;

  exit(0);
}


void SpecialFunctionHandler::handle__intercept_malloc(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  auto size = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[1]))->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);
  auto addr = mem->TryMalloc(size, executor.policy_handler.get());
  executor.bindLocal(target, state, ConstantExpr::create(addr, 64));
}


void SpecialFunctionHandler::handle__intercept_free(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_uint = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  auto ptr = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[1]))->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);
  executor.bindLocal(target, state, ConstantExpr::create(mem->TryFree(ptr, executor.policy_handler.get()), Expr::Bool));
}



void SpecialFunctionHandler::handle__symbolic_stdin(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.bindLocal(target, state, ConstantExpr::create(executor.symbolicStdin, Expr::Bool));
}


ref<Expr> SpecialFunctionHandler::runtime_write_8(ExecutionState &state,
                                                  uint64_t addr_uint,
                                                  ref<Expr> val,
                                                  native::AddressSpace *mem,
                                                  ref<Expr> mem_ptr) {
  if (auto const_val = llvm::dyn_cast<ConstantExpr>(val)) {
    return runtime_write_8(state, addr_uint,
                           static_cast<uint8_t>(const_val->getZExtValue(8)),
                           mem, mem_ptr);
  }

  if (!mem->TryWrite(addr_uint, klee::native::kSymbolicByte, executor.policy_handler.get())) {
    auto addr_space_id = llvm::dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
    std::stringstream ss;
    ss << "Failed 1-byte write of symbol to address 0x"
       << addr_uint << " in address space " << addr_space_id;
    executor.terminateStateOnError(state, ss.str(), Executor::ReportError);
    return Expr::createPointer(0);
  }

  mem->symbolic_memory[addr_uint] = val;
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_8(ExecutionState &state,
                                                  uint64_t addr_uint,
                                                  uint8_t val,
                                                  native::AddressSpace *mem,
                                                  ref<Expr> mem_ptr) {
  if (val == klee::native::kSymbolicByte) {
    mem->symbolic_memory.erase(addr_uint);
  }

  if (!mem->TryWrite(addr_uint, val, executor.policy_handler.get())) {
    auto addr_space_id = llvm::dyn_cast<ConstantExpr>(mem_ptr)->getZExtValue();
    std::stringstream ss;
    ss << "Failed 1-byte write of " << std::hex << unsigned(val)
       << " to address 0x" << addr_uint << " in address space "
       << addr_space_id;
    executor.terminateStateOnError(state, ss.str(), Executor::ReportError);
    return Expr::createPointer(0);
  }

  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_16(ExecutionState &state,
                                                   uint64_t addr_uint,
                                                   ref<Expr> val,
                                                   native::AddressSpace *mem,
                                                   ref<Expr> mem_ptr) {
  //std::string out;
  //llvm::raw_string_ostream os(out);
  //val->print(os);
  //os.flush();
  //LOG(ERROR)
  //    << "Writing 2 bytes to addr=" << std::hex << addr_uint << " val=" << out << std::dec;

  if (auto const_val = llvm::dyn_cast<ConstantExpr>(val)) {
    auto v = const_val->getZExtValue(16);
    mem_ptr = runtime_write_8(state, addr_uint + 0,
                              static_cast<uint8_t>(v >> 0), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 1,
                              static_cast<uint8_t>(v >> 8), mem, mem_ptr);
  } else {
    auto byte0 = constant_folding_builder->Extract(val, 0, 8);
    auto byte1 = constant_folding_builder->Extract(val, 8, 8);
    mem_ptr = runtime_write_8(state, addr_uint + 0, byte0, mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 1, byte1, mem, mem_ptr);
  }
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_32(ExecutionState &state,
                                                   uint64_t addr_uint,
                                                   ref<Expr> val,
                                                   native::AddressSpace *mem,
                                                   ref<Expr> mem_ptr) {
  //std::string out;
  //llvm::raw_string_ostream os(out);
  //val->print(os);
  //os.flush();
  //LOG(ERROR)
  //    << "Writing 4 bytes to addr=" << std::hex << addr_uint << " val=" << out << std::dec;

  if (auto const_val = llvm::dyn_cast<ConstantExpr>(val)) {
    auto v = const_val->getZExtValue(32);
    mem_ptr = runtime_write_8(state, addr_uint + 0,
                              static_cast<uint8_t>(v >> 0), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 1,
                              static_cast<uint8_t>(v >> 8), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 2,
                              static_cast<uint8_t>(v >> 16), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 3,
                              static_cast<uint8_t>(v >> 24), mem, mem_ptr);
  } else {
    auto byte0 = constant_folding_builder->Extract(val, 0, 8);
    auto byte1 = constant_folding_builder->Extract(val, 8, 8);
    auto byte2 = constant_folding_builder->Extract(val, 16, 8);
    auto byte3 = constant_folding_builder->Extract(val, 24, 8);
    (void) runtime_write_8(state, addr_uint + 0, byte0, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 1, byte1, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 2, byte2, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 3, byte3, mem, mem_ptr);
  }
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_write_64(ExecutionState &state,
                                                   uint64_t addr_uint,
                                                   ref<Expr> val,
                                                   native::AddressSpace *mem,
                                                   ref<Expr> mem_ptr) {
  //std::string out;
  //llvm::raw_string_ostream os(out);
  //val->print(os);
  //os.flush();
  //LOG(ERROR)
  //    << "Writing 8 bytes to addr=" << std::hex << addr_uint << " val=" << out << std::dec;

  if (auto const_val = llvm::dyn_cast<ConstantExpr>(val)) {
    auto v = const_val->getZExtValue();
    mem_ptr = runtime_write_8(state, addr_uint + 0,
                              static_cast<uint8_t>(v >> 0ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 1,
                              static_cast<uint8_t>(v >> 8ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 2,
                              static_cast<uint8_t>(v >> 16ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 3,
                              static_cast<uint8_t>(v >> 24ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 4,
                              static_cast<uint8_t>(v >> 32ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 5,
                              static_cast<uint8_t>(v >> 40ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 6,
                              static_cast<uint8_t>(v >> 48ull), mem, mem_ptr);
    mem_ptr = runtime_write_8(state, addr_uint + 7,
                              static_cast<uint8_t>(v >> 56ull), mem, mem_ptr);
  } else {
    auto byte0 = constant_folding_builder->Extract(val, 0, 8);
    auto byte1 = constant_folding_builder->Extract(val, 8, 8);
    auto byte2 = constant_folding_builder->Extract(val, 16, 8);
    auto byte3 = constant_folding_builder->Extract(val, 24, 8);
    auto byte4 = constant_folding_builder->Extract(val, 32, 8);
    auto byte5 = constant_folding_builder->Extract(val, 40, 8);
    auto byte6 = constant_folding_builder->Extract(val, 48, 8);
    auto byte7 = constant_folding_builder->Extract(val, 56, 8);
    (void) runtime_write_8(state, addr_uint + 0, byte0, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 1, byte1, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 2, byte2, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 3, byte3, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 4, byte4, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 5, byte5, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 6, byte6, mem, mem_ptr);
    (void) runtime_write_8(state, addr_uint + 7, byte7, mem, mem_ptr);
  }
  return mem_ptr;
}

ref<Expr> SpecialFunctionHandler::runtime_read_memory(
    native::AddressSpace *mem, uint64_t addr, uint64_t num_bytes,
    const MemoryReadResult &val) {

  /*
  LOG(INFO) << "Reading addr=" << std::hex << addr
            << " num_bytes=" << std::dec << num_bytes << " bytes=[" << std::hex
            << unsigned(val.as_bytes[0]) << ", " << unsigned(val.as_bytes[1]) << ", "
            << unsigned(val.as_bytes[2]) << ", " << unsigned(val.as_bytes[3]) << ", "
            << unsigned(val.as_bytes[4]) << ", " << unsigned(val.as_bytes[5]) << ", "
            << unsigned(val.as_bytes[6]) << ", " << unsigned(val.as_bytes[7]) << "]";
  */
  bool any_symbolic = false;
  bool all_symbolic = true;

  ref<klee::Expr> symbolic_bytes[8] = {};
  for (uint64_t i = 0; i < num_bytes; ++i) {
    if (val.as_bytes[i] == klee::native::kSymbolicByte) {
      const auto sym_pair = mem->symbolic_memory.find(addr + i);
      if (sym_pair != mem->symbolic_memory.end()) {
        symbolic_bytes[num_bytes-1-i] = sym_pair->second;
        any_symbolic = true;
      } else {
        all_symbolic = false;
      }
    } else {
      all_symbolic = false;
    }
  }

  //LOG(INFO) << "any_symbolic: " << any_symbolic;
  //LOG(INFO) << "all_symbolic: " << all_symbolic;
  
  if (!any_symbolic) {
    return ConstantExpr::create(val.as_qword, num_bytes * 8);
  }

  if (num_bytes == 1) {
    //LOG(INFO) << "Read symbolic byte from " << std::hex << addr << std::dec;
    //symbolic_bytes[num_bytes - 1]->dump();
    return symbolic_bytes[num_bytes - 1];
  }

  if (!all_symbolic) {
    //LOG(INFO) << "hit not all bytes symbolic case";
    for (uint64_t i = 0; i < num_bytes; ++i) {
      if (symbolic_bytes[num_bytes-1-i].isNull()) {
        symbolic_bytes[num_bytes-1-i] = ConstantExpr::create(val.as_bytes[i], 8);
      }
    }
  }

  return ConcatExpr::createN(static_cast<unsigned>(num_bytes), symbolic_bytes);
}

void SpecialFunctionHandler::handle_klee_init_remill_mem(
  ExecutionState &state, KInstruction *target,
  std::vector<ref<Expr>> &arguments) {
  auto memory_val = executor.toUnique(state, arguments[0]);
  auto memory_uint = llvm::dyn_cast<ConstantExpr>(memory_val)->getZExtValue();
  if (memory_uint >= executor.memories.size()) {
    std::stringstream ss;
    ss << "Cannot copy invalid address space " << memory_uint
       << " into state";
    executor.terminateStateOnError(state, ss.str(), Executor::ReportError);
    return;
  }

  auto mem = executor.memories[memory_uint];
  auto new_size = memory_uint + 1ULL;
  while (state.memories.size() < new_size) {
    state.memories.emplace_back(new klee::native::AddressSpace);
    state.memories.back()->Kill();
  }

  if (mem->IsDead()) {
    LOG(INFO) << "Killing address space " << memory_uint << " in state";
    state.memories[memory_uint]->Kill();

  } else {
    LOG(INFO) << "Copying address space " << memory_uint << " into state";
    state.memories[memory_uint].reset(new klee::native::AddressSpace(*mem));
  }
}

void SpecialFunctionHandler::handle__kleemill_log_state(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {}

void SpecialFunctionHandler::handle_openat64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dirfd_val = executor.toUnique(state, arguments[0]);
  auto dirfd_uint = llvm::dyn_cast<ConstantExpr>(dirfd_val)->getZExtValue();

  auto pathname_val = executor.toUnique(state, arguments[1]);
  auto pathname_uint =
      llvm::dyn_cast<ConstantExpr>(pathname_val)->getZExtValue();
  auto pathname = reinterpret_cast<char *>(pathname_uint);

  auto flags_val = executor.toUnique(state, arguments[2]);
  auto flags_uint = llvm::dyn_cast<ConstantExpr>(flags_val)->getZExtValue();

  auto mode_val = executor.toUnique(state, arguments[3]);
  auto mode_uint = llvm::dyn_cast<ConstantExpr>(mode_val)->getZExtValue();

  auto open_status = openat(dirfd_uint, pathname, flags_uint, mode_uint);

  if (open_status == -1) {
    executor.bindLocal(target, state,
                       ConstantExpr::create(open_status, Expr::Int32));
    errno = ENOENT;
  } else {
    executor.bindLocal(target, state,
                       ConstantExpr::create(open_status, Expr::Int64));
    errno = 0;
  }
}

enum {
  kStatDev,
  kStatInode,
  kStatMode,
  kStatLink,
  kStatUserId,
  kStatGroupId,
  kStatRDev,
  kStatSize,
  kStatBlockSize,
  kStatBlocks
};

void SpecialFunctionHandler::set_up_fstat_struct(struct stat *info) {
  fstat_vector.resize(10);
  fstat_vector[kStatDev] = static_cast<uint64_t>(info->st_dev);
  fstat_vector[kStatInode] = static_cast<uint64_t>(info->st_ino);
  fstat_vector[kStatMode] = static_cast<uint64_t>(info->st_mode);
  fstat_vector[kStatLink] = static_cast<uint64_t>(info->st_nlink);
  fstat_vector[kStatUserId] = static_cast<uint64_t>(info->st_uid);
  fstat_vector[kStatGroupId] = static_cast<uint64_t>(info->st_gid);
  fstat_vector[kStatRDev] = static_cast<uint64_t>(info->st_rdev);
  fstat_vector[kStatSize] = static_cast<uint64_t>(info->st_size);
  fstat_vector[kStatBlockSize] = static_cast<uint64_t>(info->st_blksize);
  fstat_vector[kStatBlocks] = static_cast<uint64_t>(info->st_blocks);
}

void SpecialFunctionHandler::handle_get_fstat_index(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto fstat_index_val = executor.toUnique(state, arguments[0]);
  auto index_uint =
      llvm::dyn_cast<ConstantExpr>(fstat_index_val)->getZExtValue();

  executor.bindLocal(
      target, state,
      ConstantExpr::create(fstat_vector[index_uint], Expr::Int64));
}

void SpecialFunctionHandler::handle_get_dirent_name(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.bindLocal(
      target, state,
      Expr::createPointer(reinterpret_cast<uintptr_t>(dirent_entry_name.data())));
}

void SpecialFunctionHandler::handle_get_dirent_index(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dirent_index_val = executor.toUnique(state, arguments[0]);
  auto index_uint =
      llvm::dyn_cast<ConstantExpr>(dirent_index_val)->getZExtValue();
  executor.bindLocal(target, state, ConstantExpr::create(dirent_entry[index_uint], Expr::Int64));
}

void SpecialFunctionHandler::set_up_dirent_struct(struct dirent *info,
                                                  long offset) {
  dirent_entry.resize(4);
  dirent_entry[0] = info->d_ino;
  dirent_entry[1] = static_cast<uint64_t>(offset);
  dirent_entry[2] = info->d_reclen;
  dirent_entry[3] = info->d_type;
  auto len = strnlen(info->d_name, sizeof(info->d_name));
  dirent_entry_name.resize(len);
  memcpy(&(dirent_entry_name[0]), info->d_name, len);
  if (dirent_entry_name.empty() || !dirent_entry_name.back()) {
    dirent_entry_name.push_back('\0');
  }
}

void SpecialFunctionHandler::handle__my_readdir(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto dir_val = executor.toUnique(state, arguments[0]);
  auto dir_uint = llvm::dyn_cast<ConstantExpr>(dir_val)->getZExtValue();

  auto dir = reinterpret_cast<DIR *>(dir_uint);
  auto offset = telldir(dir);
  auto dirent = readdir(dir);

  // must set errno
  if (!dirent) {
    executor.bindLocal(target, state, ConstantExpr::create(false, Expr::Bool));
  } else {
    set_up_dirent_struct(dirent, offset);
    executor.bindLocal(target, state, ConstantExpr::create(true, Expr::Bool));
  }
}

void SpecialFunctionHandler::handle__fstat64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto fd_val = executor.toUnique(state, arguments[0]);
  auto fd_uint = llvm::dyn_cast<ConstantExpr>(fd_val)->getZExtValue();

  struct stat stat_data = {};
  auto stat_ret = fstat(fd_uint, &stat_data);
  auto err = errno;

  executor.bindLocal(target, state,
                     ConstantExpr::create(stat_ret, Expr::Int32));

  if (stat_ret != -1) {
    set_up_fstat_struct(&stat_data);
  }

  errno = err;
}


void SpecialFunctionHandler::handle__lstat64(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto path_val = executor.toUnique(state, arguments[0]);
    auto path_uint = llvm::dyn_cast<ConstantExpr>(path_val)->getZExtValue();
    const char *pathname = reinterpret_cast<char *>(path_uint);

    struct stat stat_data = {};
    auto stat_ret = lstat(pathname, &stat_data);
    auto err = errno;

    executor.bindLocal(target, state,
                       ConstantExpr::create(stat_ret, Expr::Int32));

    if (stat_ret != -1) {
      set_up_fstat_struct(&stat_data);
    }

    errno = err;
}

void SpecialFunctionHandler::handle__stat64(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  auto path_val = executor.toUnique(state, arguments[0]);
  auto path_uint = llvm::dyn_cast<ConstantExpr>(path_val)->getZExtValue();
  const char *pathname = reinterpret_cast<char *>(path_uint);

  struct stat stat_data = {};
  auto stat_ret = stat(pathname, &stat_data);
  auto err = errno;

  executor.bindLocal(target, state,
                     ConstantExpr::create(stat_ret, Expr::Int32));

  if (stat_ret != -1) {
    set_up_fstat_struct(&stat_data);
  }

  errno = err;
}

void SpecialFunctionHandler::handle__klee_overshift_check(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto shift_val = executor.toUnique(state, arguments[0]);
  auto shift_uint = llvm::dyn_cast<ConstantExpr>(shift_val)->getZExtValue();

  auto bitWidth_val = executor.toUnique(state, arguments[1]);
  auto bitWidth_uint =
      llvm::dyn_cast<ConstantExpr>(bitWidth_val)->getZExtValue();

  if (shift_uint >= bitWidth_uint) {
    LOG(ERROR) << "overshift has occured";
  }
}

void SpecialFunctionHandler::handle__kleemill_can_read_byte(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto addr_val = executor.toUnique(state, arguments[1]);
  auto addr_uint = llvm::dyn_cast<ConstantExpr>(addr_val)->getZExtValue();


  bool can_read = mem->CanRead(addr_uint);

  executor.bindLocal(target, state, ConstantExpr::create(can_read, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_can_write_byte(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  //LOG(INFO) << "addressspace num is " << mem_uint;

  auto addr_val = executor.toUnique(state, arguments[1]);
  auto addr_uint = llvm::dyn_cast<ConstantExpr>(addr_val)->getZExtValue();


  bool can_write = mem->CanWrite(addr_uint);

  executor.bindLocal(target, state,
                     ConstantExpr::create(can_write, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_free_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();


  mem->RemoveMap(where_uint, size_uint);

  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_allocate_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto name_val = executor.toUnique(state, arguments[3]);
  auto name_uint = llvm::dyn_cast<ConstantExpr>(name_val)->getZExtValue();
  auto name_char = reinterpret_cast<char *>(name_uint);

  auto offset_val = executor.toUnique(state, arguments[4]);
  auto offset_uint = llvm::dyn_cast<ConstantExpr>(offset_val)->getZExtValue();

  mem->AddMap(where_uint, size_uint, name_char, offset_uint);
  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_protect_memory(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[2]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto can_read_val = executor.toUnique(state, arguments[3]);
  auto can_read_uint =
      llvm::dyn_cast<ConstantExpr>(can_read_val)->getZExtValue();

  auto can_write_val = executor.toUnique(state, arguments[4]);
  auto can_write_uint =
      llvm::dyn_cast<ConstantExpr>(can_write_val)->getZExtValue();

  auto can_exec_val = executor.toUnique(state, arguments[5]);
  auto can_exec_uint =
      llvm::dyn_cast<ConstantExpr>(can_exec_val)->getZExtValue();

  mem->SetPermissions(where_uint, size_uint, static_cast<bool>(can_read_uint),
                      static_cast<bool>(can_write_uint),
                      static_cast<bool>(can_exec_uint));
  executor.bindLocal(target, state, mem_val);
}

void SpecialFunctionHandler::handle__kleemill_is_mapped_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto where_val = executor.toUnique(state, arguments[1]);
  auto where_uint = llvm::dyn_cast<ConstantExpr>(where_val)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);

  bool is_mapped = mem->IsMapped(where_uint);

  executor.bindLocal(target, state,
                     ConstantExpr::create(is_mapped, Expr::Bool));
}

void SpecialFunctionHandler::handle__kleemill_find_unmapped_address(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {

  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();

  //LOG(INFO) << "addressspace num is " << mem_uint;
  auto base_val = executor.toUnique(state, arguments[1]);
  auto base_uint = llvm::dyn_cast<ConstantExpr>(base_val)->getZExtValue();

  auto limit_val = executor.toUnique(state, arguments[2]);
  auto limit_uint = llvm::dyn_cast<ConstantExpr>(limit_val)->getZExtValue();

  auto size_val = executor.toUnique(state, arguments[3]);
  auto size_uint = llvm::dyn_cast<ConstantExpr>(size_val)->getZExtValue();

  auto mem = executor.Memory(state, mem_uint);

  uint64_t hole = 0;
  if (mem->FindHole(base_uint, limit_uint, size_uint, &hole)) {
    executor.bindLocal(target, state, ConstantExpr::create(hole, Expr::Int64));
  } else {
    executor.bindLocal(target, state, ConstantExpr::create(0, Expr::Int64));
  }
}

#define HANDLE_READ(num_bits, num_bytes, bits_type) \
    void SpecialFunctionHandler::handle__remill_read_ ## num_bits( \
        ExecutionState &state, KInstruction *target, \
        std::vector<ref<Expr>> &arguments) { \
      \
      auto mem_val = executor.toUnique(state, arguments[0]); \
      auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue(); \
      auto memory = executor.Memory(state, mem_uint); \
      auto addr_val = executor.toUnique(state, arguments[1]); \
      \
      if (auto const_addr = llvm::dyn_cast<klee::ConstantExpr>(addr_val)) { \
        auto addr_uint = const_addr->getZExtValue(); \
        MemoryReadResult result = {}; \
        if (memory->TryRead(addr_uint, result.as_bytes, num_bytes, executor.policy_handler.get())) { \
          executor.bindLocal( \
              target, state, runtime_read_memory(memory, addr_uint, \
                                                 num_bytes, result)); \
        } else { \
          std::stringstream ss; \
          ss << "Can't read " << num_bytes << " from " \
             << std::hex << addr_uint; \
          executor.terminateStateOnError( \
              state, ss.str(), Executor::ReportError); \
        } \
      } else { \
        auto range = executor.solver->getRange(state, addr_val); \
        auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first); \
        auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second); \
        auto min_uint = min->getZExtValue(); \
        auto max_uint = max->getZExtValue(); \
        auto mem_cont = new MemoryAccessContinuation( \
            &state, addr_val, min_uint, max_uint, min_uint, mem_uint, mem_val, \
            MemoryContinuationKind::kContinueRead ## num_bits); \
        executor.continuations.emplace_back(mem_cont); \
        if (&state != mem_cont->YieldNextState(executor)) { \
          executor.continuations.pop_back(); \
        } \
      } \
    }

HANDLE_READ(8, 1, as_byte)
HANDLE_READ(16, 2, as_word)
HANDLE_READ(32, 4, as_dword)
HANDLE_READ(64, 8, as_qword)
#undef HANDLE_READ

#define HANDLE_WRITE(num_bits, num_bytes) \
    void SpecialFunctionHandler::handle__remill_write_ ## num_bits ( \
        ExecutionState &state, KInstruction *target, \
        std::vector<ref<Expr>> &arguments) { \
      \
      auto mem_val = executor.toUnique(state, arguments[0]); \
      auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue(); \
      auto memory = executor.Memory(state, mem_uint); \
      auto addr_val = executor.toUnique(state, arguments[1]); \
      auto val = executor.toUnique(state, arguments[2]); \
      \
      if (auto const_addr = llvm::dyn_cast<ConstantExpr>(addr_val)) { \
        auto addr_uint = const_addr->getZExtValue(); \
        executor.bindLocal(target, state, runtime_write_ ## num_bits( \
            state, addr_uint, val, memory, mem_val)); \
      } else { \
        auto range = executor.solver->getRange(state, addr_val); \
        auto min = llvm::dyn_cast<klee::ConstantExpr>(range.first); \
        auto max = llvm::dyn_cast<klee::ConstantExpr>(range.second); \
        auto min_uint = min->getZExtValue(); \
        auto max_uint = max->getZExtValue(); \
        auto mem_cont = new MemoryAccessContinuation( \
            &state, addr_val, min_uint, max_uint, min_uint, mem_uint, mem_val, \
            MemoryContinuationKind::kContinueWrite ## num_bits); \
        executor.continuations.emplace_back(mem_cont); \
        mem_cont->val_to_write = val; \
        if (&state != mem_cont->YieldNextState(executor)) { \
          executor.continuations.pop_back(); \
        } \
      } \
    }

HANDLE_WRITE(8, 1)
HANDLE_WRITE(16, 2)
HANDLE_WRITE(32, 4)
HANDLE_WRITE(64, 8)
#undef HANDLE_WRITE

void SpecialFunctionHandler::handle__llvm_ctpop(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto pc_val = executor.toUnique(state, arguments[0]);
  auto pc_uint = llvm::dyn_cast<ConstantExpr>(pc_val)->getZExtValue();

  auto ctop_val = __builtin_popcount(pc_uint);
  LOG(INFO) << ctop_val << " : LLVM CTPOP VALUE";
  executor.bindLocal(target, state,
                     ConstantExpr::create(ctop_val, Expr::Int32));
}

void SpecialFunctionHandler::handle__kleemill_get_lifted_function(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  auto mem_val = executor.toUnique(state, arguments[0]);
  auto mem_uint = llvm::dyn_cast<ConstantExpr>(mem_val)->getZExtValue();
  auto mem = executor.Memory(state, mem_uint);

  auto pc_val = executor.toUnique(state, arguments[1]);
  auto pc_uint = llvm::dyn_cast<ConstantExpr>(pc_val)->getZExtValue();

  auto func = executor.GetLiftedFunction(mem, pc_uint);

  executor.bindLocal(target, state,
                     Expr::createPointer(reinterpret_cast<uintptr_t>(func)));
}

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::begin() {
  return SpecialFunctionHandler::const_iterator(handlerInfo);
}

SpecialFunctionHandler::const_iterator SpecialFunctionHandler::end() {
  // NULL pointer is sentinel
  return SpecialFunctionHandler::const_iterator(0);
}

SpecialFunctionHandler::const_iterator &SpecialFunctionHandler::const_iterator::
operator++() {
  ++index;
  if (index >= SpecialFunctionHandler::size()) {
    // Out of range, return .end()
    base = 0; // Sentinel
    index = 0;
  }

  return *this;
}

int SpecialFunctionHandler::size() {
  return sizeof(handlerInfo) / sizeof(handlerInfo[0]);
}

SpecialFunctionHandler::SpecialFunctionHandler(Executor &_executor)
    : executor(_executor),
      default_builder(createDefaultExprBuilder()),
      constant_folding_builder(
          createConstantFoldingExprBuilder(default_builder.get())) {
}


void SpecialFunctionHandler::prepare(
    llvm::Module *mod, std::vector<const char *> &preservedFunctions) {
  unsigned N = size();

  for (unsigned i = 0; i < N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = mod->getFunction(hi.name);

    // No need to create if the function doesn't exist, since it cannot
    // be called in that case.
    if (f && (!hi.doNotOverride || f->isDeclaration())) {
      preservedFunctions.push_back(hi.name);
      // Make sure NoReturn attribute is set, for optimization and
      // coverage counting.
      if (hi.doesNotReturn)
        f->addFnAttr(Attribute::NoReturn);

      // Change to a declaration since we handle internally (simplifies
      // module and allows deleting dead code).
      if (!f->isDeclaration())
        f->deleteBody();
    }
  }
}

void SpecialFunctionHandler::bind(llvm::Module *mod) {
  unsigned N = sizeof(handlerInfo) / sizeof(handlerInfo[0]);

  for (unsigned i = 0; i < N; ++i) {
    HandlerInfo &hi = handlerInfo[i];
    Function *f = mod->getFunction(hi.name);

    if (f && (!hi.doNotOverride || f->isDeclaration()))
      handlers[f] = std::make_pair(hi.handler, hi.hasReturnValue);
  }
}

bool SpecialFunctionHandler::handle(ExecutionState &state, Function *f,
                                    KInstruction *target,
                                    std::vector<ref<Expr>> &arguments) {
  handlers_ty::iterator it = handlers.find(f);
  if (it != handlers.end()) {
    Handler h = it->second.first;
    bool hasReturnValue = it->second.second;
    // FIXME: Check this... add test?
    if (!hasReturnValue && !target->inst->use_empty()) {
      executor.terminateStateOnExecError(
          state, "expected return value from void special function");
    } else {
      (this->*h)(state, target, arguments);
    }
    return true;
  } else {
    return false;
  }
}

/****/

// reads a concrete string from memory
std::string SpecialFunctionHandler::readStringAtAddress(ExecutionState &state,
                                                        ref<Expr> addressExpr) {
  ObjectPair op;
  addressExpr = executor.toUnique(state, addressExpr);
  if (!isa<ConstantExpr>(addressExpr)) {
    executor.terminateStateOnError(
        state, "Symbolic string pointer passed to one of the klee_ functions",
        Executor::TerminateReason::User);
    return "";
  }
  ref<ConstantExpr> address = cast<ConstantExpr>(addressExpr);
  if (!state.addressSpace.resolveOne(address, op)) {
    executor.terminateStateOnError(
        state, "Invalid string pointer passed to one of the klee_ functions",
        Executor::TerminateReason::User);
    return "";
  }
  bool res __attribute__((unused));
  assert(executor.solver->mustBeTrue(
             state, EqExpr::create(address, op.first->getBaseExpr()), res) &&
         res && "XXX interior pointer unhandled");
  const MemoryObject *mo = op.first;
  const ObjectState *os = op.second;

  char *buf = new char[mo->size];

  unsigned i;
  for (i = 0; i < mo->size - 1; i++) {
    ref<Expr> cur = os->read8(i);
    cur = executor.toUnique(state, cur);
    assert(isa<ConstantExpr>(cur) &&
           "hit symbolic char while reading concrete string");
    buf[i] = cast<ConstantExpr>(cur)->getZExtValue(8);
  }
  buf[i] = 0;

  std::string result(buf);
  delete[] buf;
  return result;
}

/****/

void SpecialFunctionHandler::handleAbort(ExecutionState &state,
                                         KInstruction *target,
                                         std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 0 && "invalid number of arguments to abort");
  executor.terminateStateOnError(state, "abort failure", Executor::Abort);
}

void SpecialFunctionHandler::handleExit(ExecutionState &state,
                                        KInstruction *target,
                                        std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateStateOnExit(state);
}

void SpecialFunctionHandler::handleSilentExit(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to exit");
  executor.terminateState(state);
}

void SpecialFunctionHandler::handleAliasFunction(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_alias_function");
  std::string old_fn = readStringAtAddress(state, arguments[0]);
  std::string new_fn = readStringAtAddress(state, arguments[1]);
  KLEE_DEBUG_WITH_TYPE("alias_handling", llvm::errs()
                                             << "Replacing " << old_fn
                                             << "() with " << new_fn << "()\n");
  if (old_fn == new_fn)
    state.removeFnAlias(old_fn);
  else
    state.addFnAlias(old_fn, new_fn);
}

void SpecialFunctionHandler::handleAssert(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 3 && "invalid number of arguments to _assert");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      Executor::Assert);
}

void SpecialFunctionHandler::handleAssertFail(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to __assert_fail");
  executor.terminateStateOnError(
      state, "ASSERTION FAIL: " + readStringAtAddress(state, arguments[0]),
      Executor::Assert);
}

void SpecialFunctionHandler::handleReportError(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 4 &&
         "invalid number of arguments to klee_report_error");

  // arguments[0], arguments[1] are file, line
  executor.terminateStateOnError(
      state, readStringAtAddress(state, arguments[2]), Executor::ReportError,
      readStringAtAddress(state, arguments[3]).c_str());
}

void SpecialFunctionHandler::handleOpenMerge(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_open_merge ignored, use '-use-merge'");
    return;
  }

  state.openMergeStack.push_back(
      ref<MergeHandler>(new MergeHandler(&executor, &state)));

  if (DebugLogMerge)
    llvm::errs() << "open merge: " << &state << "\n";
}

void SpecialFunctionHandler::handleCloseMerge(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (!UseMerge) {
    klee_warning_once(0, "klee_close_merge ignored, use '-use-merge'");
    return;
  }
  Instruction *i = target->inst;

  if (DebugLogMerge)
    llvm::errs() << "close merge: " << &state << " at " << i << '\n';

  if (state.openMergeStack.empty()) {
    std::ostringstream warning;
    warning << &state << " ran into a close at " << i
            << " without a preceding open";
    klee_warning("%s", warning.str().c_str());
  } else {
    assert(executor.inCloseMerge.find(&state) == executor.inCloseMerge.end() &&
           "State cannot run into close_merge while being closed");
    executor.inCloseMerge.insert(&state);
    state.openMergeStack.back()->addClosedState(&state, i);
    state.openMergeStack.pop_back();
  }
}

void SpecialFunctionHandler::handleNew(ExecutionState &state,
                                       KInstruction *target,
                                       std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to new");

  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDelete(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // FIXME: Should check proper pairing with allocation type (malloc/free,
  // new/delete, new[]/delete[]).

  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to delete");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleNewArray(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to new[]");
  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleDeleteArray(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to delete[]");
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleMalloc(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to malloc");

  executor.executeAlloc(state, arguments[0], false, target);
}

void SpecialFunctionHandler::handleMemalign(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  if (arguments.size() != 2) {
    executor.terminateStateOnError(state,
                                   "Incorrect number of arguments to "
                                   "memalign(size_t alignment, size_t size)",
                                   Executor::User);
    return;
  }

  std::pair<ref<Expr>, ref<Expr>> alignmentRangeExpr =
      executor.solver->getRange(state, arguments[0]);
  ref<Expr> alignmentExpr = alignmentRangeExpr.first;
  auto alignmentConstExpr = dyn_cast<ConstantExpr>(alignmentExpr);

  if (!alignmentConstExpr) {
    executor.terminateStateOnError(
        state, "Could not determine size of symbolic alignment",
        Executor::User);
    return;
  }

  uint64_t alignment = alignmentConstExpr->getZExtValue();

  // Warn, if the expression has more than one solution
  if (alignmentRangeExpr.first != alignmentRangeExpr.second) {
    klee_warning_once(
        0, "Symbolic alignment for memalign. Choosing smallest alignment");
  }

  executor.executeAlloc(state, arguments[1], false, target, false, 0,
                        alignment);
}

void SpecialFunctionHandler::handleAssume(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 && "invalid number of arguments to klee_assume");

  ref<Expr> e = arguments[0];

  if (e->getWidth() != Expr::Bool)
    e = NeExpr::create(e, ConstantExpr::create(0, e->getWidth()));

  bool res;
  bool success __attribute__((unused)) =
      executor.solver->mustBeFalse(state, e, res);
  assert(success && "FIXME: Unhandled solver failure");
  if (res) {
    if (SilentKleeAssume) {
      executor.terminateState(state);
    } else {
      executor.terminateStateOnError(
          state, "invalid klee_assume call (provably false)", Executor::User);
    }
  } else {
    executor.addConstraint(state, e);
  }
}

void SpecialFunctionHandler::handleIsSymbolic(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_is_symbolic");

  executor.bindLocal(
      target, state,
      ConstantExpr::create(!isa<ConstantExpr>(arguments[0]), Expr::Int32));
}

void SpecialFunctionHandler::handlePreferCex(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_prefex_cex");

  ref<Expr> cond = arguments[1];
  if (cond->getWidth() != Expr::Bool)
    cond = NeExpr::create(cond, ConstantExpr::alloc(0, cond->getWidth()));

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "prefex_cex");

  assert(rl.size() == 1 &&
         "prefer_cex target must resolve to precisely one object");

  rl[0].first.first->cexPreferences.push_back(cond);
}

void SpecialFunctionHandler::handlePosixPreferCex(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  if (ReadablePosix)
    return handlePreferCex(state, target, arguments);
}

void SpecialFunctionHandler::handlePrintExpr(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_print_expr");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1] << "\n";
}

void SpecialFunctionHandler::handleSetForking(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_set_forking");
  ref<Expr> value = executor.toUnique(state, arguments[0]);

  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(value)) {
    state.forkDisabled = CE->isZero();
  } else {
    executor.terminateStateOnError(
        state, "klee_set_forking requires a constant arg", Executor::User);
  }
}

void SpecialFunctionHandler::handleStackTrace(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  state.dumpStack(outs());
}

void SpecialFunctionHandler::handleWarning(ExecutionState &state,
                                           KInstruction *target,
                                           std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_warning");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning("%s: %s", state.stack.back().kf->function->getName().data(),
               msg_str.c_str());
}

void SpecialFunctionHandler::handleWarningOnce(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_warning_once");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  klee_warning_once(0, "%s: %s",
                    state.stack.back().kf->function->getName().data(),
                    msg_str.c_str());
}

void SpecialFunctionHandler::handlePrintRange(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_print_range");

  std::string msg_str = readStringAtAddress(state, arguments[0]);
  llvm::errs() << msg_str << ":" << arguments[1];
  if (!isa<ConstantExpr>(arguments[1])) {
    // FIXME: Pull into a unique value method?
    ref<ConstantExpr> value;
    bool success __attribute__((unused)) =
        executor.solver->getValue(state, arguments[1], value);
    assert(success && "FIXME: Unhandled solver failure");
    bool res;
    success = executor.solver->mustBeTrue(
        state, EqExpr::create(arguments[1], value), res);
    assert(success && "FIXME: Unhandled solver failure");
    if (res) {
      llvm::errs() << " == " << value;
    } else {
      llvm::errs() << " ~= " << value;
      std::pair<ref<Expr>, ref<Expr>> res =
          executor.solver->getRange(state, arguments[1]);
      llvm::errs() << " (in [" << res.first << ", " << res.second << "])";
    }
  }
  llvm::errs() << "\n";
}

void SpecialFunctionHandler::handleGetObjSize(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_get_obj_size");
  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "klee_get_obj_size");
  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    executor.bindLocal(
        target, *it->second,
        ConstantExpr::create(it->first.first->size,
                             executor.kmodule->targetData->getTypeSizeInBits(
                                 target->inst->getType())));
  }
}

void SpecialFunctionHandler::handleGetErrno(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 0 &&
         "invalid number of arguments to klee_get_errno");
#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  // Retrieve the memory object of the errno variable
  ObjectPair result;
  bool resolved = state.addressSpace.resolveOne(
      ConstantExpr::create((uint64_t)errno_addr, Expr::Int64), result);
  if (!resolved)
    executor.terminateStateOnError(state, "Could not resolve address for errno",
                                   Executor::User);
  executor.bindLocal(target, state, result.second->read(0, Expr::Int32));
}

void SpecialFunctionHandler::handleErrnoLocation(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  // Returns the address of the errno variable
  assert(arguments.size() == 0 &&
         "invalid number of arguments to __errno_location/__error");

#ifndef WINDOWS
  int *errno_addr = executor.getErrnoLocation(state);
#else
  int *errno_addr = nullptr;
#endif

  executor.bindLocal(
      target, state,
      ConstantExpr::create((uint64_t)errno_addr,
                           executor.kmodule->targetData->getTypeSizeInBits(
                               target->inst->getType())));
}

void SpecialFunctionHandler::handleCalloc(ExecutionState &state,
                                          KInstruction *target,
                                          std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 2 && "invalid number of arguments to calloc");

  ref<Expr> size = MulExpr::create(arguments[0], arguments[1]);
  executor.executeAlloc(state, size, false, target, true);
}

void SpecialFunctionHandler::handleRealloc(ExecutionState &state,
                                           KInstruction *target,
                                           std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 2 && "invalid number of arguments to realloc");
  ref<Expr> address = arguments[0];
  ref<Expr> size = arguments[1];

  Executor::StatePair zeroSize =
      executor.fork(state, Expr::createIsZero(size), true);

  if (zeroSize.first) { // size == 0
    executor.executeFree(*zeroSize.first, address, target);
  }
  if (zeroSize.second) { // size != 0
    Executor::StatePair zeroPointer =
        executor.fork(*zeroSize.second, Expr::createIsZero(address), true);

    if (zeroPointer.first) { // address == 0
      executor.executeAlloc(*zeroPointer.first, size, false, target);
    }
    if (zeroPointer.second) { // address != 0
      Executor::ExactResolutionList rl;
      executor.resolveExact(*zeroPointer.second, address, rl, "realloc");

      for (Executor::ExactResolutionList::iterator it = rl.begin(),
                                                   ie = rl.end();
           it != ie; ++it) {
        executor.executeAlloc(*it->second, size, false, target, false,
                              it->first.second);
      }
    }
  }
}

void SpecialFunctionHandler::handleFree(ExecutionState &state,
                                        KInstruction *target,
                                        std::vector<ref<Expr>> &arguments) {
  // XXX should type check args
  assert(arguments.size() == 1 && "invalid number of arguments to free");
  auto ptr = dyn_cast<ConstantExpr>(executor.toUnique(state, arguments[0]))->getZExtValue();
  executor.executeFree(state, arguments[0]);
}

void SpecialFunctionHandler::handleCheckMemoryAccess(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_check_memory_access");

  ref<Expr> address = executor.toUnique(state, arguments[0]);
  ref<Expr> size = executor.toUnique(state, arguments[1]);
  if (!isa<ConstantExpr>(address) || !isa<ConstantExpr>(size)) {
    executor.terminateStateOnError(
        state, "check_memory_access requires constant args", Executor::User);
  } else {
    ObjectPair op;

    if (!state.addressSpace.resolveOne(cast<ConstantExpr>(address), op)) {
      executor.terminateStateOnError(state, "check_memory_access: memory error",
                                     Executor::Ptr, NULL,
                                     executor.getAddressInfo(state, address));
    } else {
      ref<Expr> chk = op.first->getBoundsCheckPointer(
          address, cast<ConstantExpr>(size)->getZExtValue());
      if (!chk->isTrue()) {
        executor.terminateStateOnError(
            state, "check_memory_access: memory error", Executor::Ptr, NULL,
            executor.getAddressInfo(state, address));
      }
    }
  }
}

void SpecialFunctionHandler::handleGetValue(ExecutionState &state,
                                            KInstruction *target,
                                            std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_get_value");

  executor.executeGetValue(state, arguments[0], target);
}

void SpecialFunctionHandler::handleDefineFixedObject(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 2 &&
         "invalid number of arguments to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[0]) &&
         "expect constant address argument to klee_define_fixed_object");
  assert(isa<ConstantExpr>(arguments[1]) &&
         "expect constant size argument to klee_define_fixed_object");

  uint64_t address = cast<ConstantExpr>(arguments[0])->getZExtValue();
  uint64_t size = cast<ConstantExpr>(arguments[1])->getZExtValue();
  MemoryObject *mo =
      executor.memory->allocateFixed(address, size, state.prevPC->inst);
  executor.bindObjectInState(state, mo, false);
  mo->isUserSpecified = true; // XXX hack;
}

void SpecialFunctionHandler::handleMakeSymbolic(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  std::string name;
  std::stringstream name_stream;

  if (arguments.size() != 3) {
    executor.terminateStateOnError(state,
                                   "Incorrect number of arguments to "
                                   "klee_make_symbolic(void*, size_t, char*)",
                                   Executor::User);
    return;
  }

  name = arguments[2]->isZero() ? "" : readStringAtAddress(state, arguments[2]);
  static int id;
  if (name.length() == 0) {
    name_stream << "unnamed" << ++id;
    name = name_stream.str();
    LOG(INFO) << "klee_make_symbolic: renamed empty name to " << name;
  }

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "make_symbolic");

  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    mo->setName(name);

    const ObjectState *old = it->first.second;
    ExecutionState *s = it->second;

    if (old->readOnly) {
      executor.terminateStateOnError(*s, "cannot make readonly object symbolic",
                                     Executor::User);
      return;
    }

    // FIXME: Type coercion should be done consistently somewhere.
    bool res;
    bool success __attribute__((unused)) = executor.solver->mustBeTrue(
        *s,
        EqExpr::create(
            ZExtExpr::create(arguments[1], Context::get().getPointerWidth()),
            mo->getSizeExpr()),
        res);
    assert(success && "FIXME: Unhandled solver failure");

    if (res) {
      executor.executeMakeSymbolic(*s, mo, name);
    } else {
      executor.terminateStateOnError(
          *s, "wrong size given to klee_make_symbolic[_name]", Executor::User);
    }
  }
}

void SpecialFunctionHandler::handleMarkGlobal(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  assert(arguments.size() == 1 &&
         "invalid number of arguments to klee_mark_global");

  Executor::ExactResolutionList rl;
  executor.resolveExact(state, arguments[0], rl, "mark_global");

  for (Executor::ExactResolutionList::iterator it = rl.begin(), ie = rl.end();
       it != ie; ++it) {
    const MemoryObject *mo = it->first.first;
    assert(!mo->isLocal);
    mo->isGlobal = true;
  }
}

void SpecialFunctionHandler::handleAddOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on addition",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleSubOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on subtraction",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleMulOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on multiplication",
                                 Executor::Overflow);
}

void SpecialFunctionHandler::handleDivRemOverflow(
    ExecutionState &state, KInstruction *target,
    std::vector<ref<Expr>> &arguments) {
  executor.terminateStateOnError(state, "overflow on division or remainder",
                                 Executor::Overflow);
}
