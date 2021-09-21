//===-- SpecialFunctionHandler.h --------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_SPECIALFUNCTIONHANDLER_H
#define KLEE_SPECIALFUNCTIONHANDLER_H

#include <iterator>
#include <unordered_set>
#include <map>
#include <vector>
#include <string>
#include <deque>
#include <dirent.h>
#include "Executor.h"
#include "klee/ExprBuilder.h"
#include "Continuation.h"

namespace llvm {
class Function;
class Module;
}  // namespace llvm


struct stat;

namespace klee {
class Executor;
class Ref;
class Expr;
class ConstantExpr;
class ExecutionState;
struct KInstruction;
template<typename T> class ref;


class SpecialFunctionHandler {
 private:
  //std::deque<ExecutionState&> jump_states;

 public:
  typedef void (SpecialFunctionHandler::*Handler)(
      ExecutionState &state, KInstruction *target,
      std::vector<ref<Expr> > &arguments);
  typedef std::map<const llvm::Function*, std::pair<Handler, bool> > handlers_ty;
  std::vector<uint64_t> fstat_vector;
  std::vector<uint64_t> sym_addrs;
 
  std::vector<uint64_t> dirent_entry;
  std::string dirent_entry_name;

  handlers_ty handlers;
  class Executor &executor;
  std::unique_ptr<ExprBuilder> default_builder;
  std::unique_ptr<ExprBuilder> constant_folding_builder;
 
  struct HandlerInfo {
    const char *name;
    SpecialFunctionHandler::Handler handler;
    bool doesNotReturn;  /// Intrinsic terminates the process
    bool hasReturnValue;  /// Intrinsic has a return value
    bool doNotOverride;  /// Intrinsic should not be used if already defined
  };

  // const_iterator to iterate over stored HandlerInfo
  // FIXME: Implement >, >=, <=, < operators
  class const_iterator : public std::iterator<std::random_access_iterator_tag,
      HandlerInfo> {
   private:
    value_type* base;
    int index;
   public:
    const_iterator(value_type* hi)
        : base(hi),
          index(0) {
    }
    ;
    const_iterator& operator++();  // pre-fix
    const_iterator operator++(int);  // post-fix
    const value_type& operator*() {
      return base[index];
    }
    const value_type* operator->() {
      return &(base[index]);
    }
    const value_type& operator[](int i) {
      return base[i];
    }
    bool operator==(const_iterator& rhs) {
      return (rhs.base + rhs.index) == (this->base + this->index);
    }
    bool operator!=(const_iterator& rhs) {
      return !(*this == rhs);
    }
  };

  static const_iterator begin();
  static const_iterator end();
  static int size();

 public:
  SpecialFunctionHandler(Executor &_executor);

  /// Perform any modifications on the LLVM module before it is
  /// prepared for execution. At the moment this involves deleting
  /// unused function bodies and marking intrinsics with appropriate
  /// flags for use in optimizations.
  ///
  /// @param preservedFunctions contains all the function names which should
  /// be preserved during optimization
  void prepare(llvm::Module *mod,
               std::vector<const char *> &preservedFunctions);

  /// Initialize the internal handler map after the module has been
  /// prepared for execution.
  void bind(llvm::Module *mod);

  bool handle(ExecutionState &state, llvm::Function *f, KInstruction *target,
              std::vector<ref<Expr> > &arguments);

  /* Convenience routines */

  std::string readStringAtAddress(ExecutionState &state, ref<Expr> address);

  void set_up_fstat_struct(struct stat *info);
  void set_up_dirent_struct(struct dirent *info, long offset);


  ref<Expr> runtime_read_memory(native::AddressSpace * mem,
                                uint64_t addr_uint, uint64_t num_bytes,
                                const MemoryReadResult &val);
  ref<Expr> runtime_write_8(ExecutionState &state, uint64_t addr_uint,
                            ref<Expr> val, native::AddressSpace *mem,
                            ref<Expr> mem_ptr);
  ref<Expr> runtime_write_8(ExecutionState &state, uint64_t addr_uint,
                            uint8_t val, native::AddressSpace *mem,
                            ref<Expr> mem_ptr);

  ref<Expr> runtime_write_16(ExecutionState &state, uint64_t addr_uint,
                             ref<Expr> value_val, native::AddressSpace *mem,
                             ref<Expr> mem_ptr);
  ref<Expr> runtime_write_32(ExecutionState &state, uint64_t addr_uint,
                             ref<Expr> value_val, native::AddressSpace *mem,
                             ref<Expr> mem_ptr);
  ref<Expr> runtime_write_64(ExecutionState &state, uint64_t addr_uint,
                             ref<Expr> value_val, native::AddressSpace *mem,
                             ref<Expr> mem_ptr);
 
  /* Handlers */

#define HANDLER(name) void name(ExecutionState &state, \
                                KInstruction *target, \
                                std::vector< ref<Expr> > &arguments)

  HANDLER(handleAbort);
  HANDLER(handleAssert);
  HANDLER(handleAssertFail);
  HANDLER(handleAssume);
  HANDLER(handleCalloc);
  HANDLER(handleCheckMemoryAccess);
  HANDLER(handleDefineFixedObject);
  HANDLER(handleDelete);
  HANDLER(handleDeleteArray);
  HANDLER(handleExit);
  HANDLER(handleErrnoLocation);
  HANDLER(handleAliasFunction);
  HANDLER(handleFree);
  HANDLER(handleGetErrno);
  HANDLER(handleGetObjSize);
  HANDLER(handleGetValue);
  HANDLER(handleIsSymbolic);
  HANDLER(handleMakeSymbolic);
  HANDLER(handleMalloc);
  HANDLER(handleMemalign);
  HANDLER(handleMarkGlobal);
  HANDLER(handleOpenMerge);
  HANDLER(handleCloseMerge);
  HANDLER(handleNew);
  HANDLER(handleNewArray);
  HANDLER(handlePreferCex);
  HANDLER(handlePosixPreferCex);
  HANDLER(handlePrintExpr);
  HANDLER(handlePrintRange);
  HANDLER(handleRange);
  HANDLER(handleRealloc);
  HANDLER(handleReportError);
  HANDLER(handleRevirtObjects);
  HANDLER(handleSetForking);
  HANDLER(handleSilentExit);
  HANDLER(handleStackTrace);
  HANDLER(handleUnderConstrained);
  HANDLER(handleWarning);
  HANDLER(handleWarningOnce);
  HANDLER(handleAddOverflow);
  HANDLER(handleMulOverflow);
  HANDLER(handleSubOverflow);
  HANDLER(handleDivRemOverflow);

  //additions for remill lifted code
  HANDLER(handle__kleemill_get_lifted_function);
  HANDLER(handle__kleemill_can_write_byte);
  HANDLER(handle__kleemill_can_read_byte);
  HANDLER(handle__kleemill_free_memory);
  HANDLER(handle__kleemill_protect_memory);
  HANDLER(handle__kleemill_allocate_memory);
  HANDLER(handle__kleemill_is_mapped_address);
  HANDLER(handle__kleemill_find_unmapped_address);
  HANDLER(handle__kleemill_log_state);
  
  HANDLER(handle__remill_write_64);
  HANDLER(handle__remill_write_32);
  HANDLER(handle__remill_write_16);
  HANDLER(handle__remill_write_8);

  HANDLER(handle__remill_read_8);
  HANDLER(handle__remill_read_16);
  HANDLER(handle__remill_read_32);
  HANDLER(handle__remill_read_64);
  
  HANDLER(handle__llvm_ctpop);

  HANDLER(handle__klee_overshift_check);
  HANDLER(handle__fstat64);
  HANDLER(handle__lstat64);
  HANDLER(handle__stat64);
  HANDLER(handle_openat64);
  HANDLER(handle_get_fstat_index);
  HANDLER(handle__my_readdir);
  HANDLER(handle_get_dirent_index);
  HANDLER(handle_get_dirent_name);
  HANDLER(handle_klee_init_remill_mem);
  HANDLER(handle__symbolic_stdin); 
  
  /* intercept handlers for libc calls */
  HANDLER(handle__intercept_strtol);
  HANDLER(handle__intercept_malloc);
  HANDLER(handle__intercept_free);
  HANDLER(handle__intercept_calloc);
  HANDLER(handle__intercept_realloc);
  HANDLER(handle_malloc_size);
//  HANDLER(handle_independent_calloc);
//  HANDLER(handle_independent_comalloc);
  HANDLER(handle_memset_intercept);
  HANDLER(handle_memcpy_intercept);
  HANDLER(handle_memmove_intercept);
  HANDLER(handle_strcpy_intercept);
  HANDLER(handle_strncpy_intercept);
  HANDLER(handle_strlen_intercept);
  HANDLER(handle_strnlen_intercept);

#undef HANDLER
};
}  // End klee namespace

#endif
