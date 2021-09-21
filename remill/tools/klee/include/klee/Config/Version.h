//===-- Version.h -----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_CONFIG_VERSION_H
#define KLEE_CONFIG_VERSION_H

#include "remill/BC/Version.h"

#define LLVM_VERSION_CODE LLVM_VERSION_NUMBER

#if LLVM_VERSION_CODE >= LLVM_VERSION(4, 0)
#  define KLEE_LLVM_CL_VAL_END
#else
#  define KLEE_LLVM_CL_VAL_END , llvm::cl::clEnumValEnd
#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(5, 0)
#  define KLEE_LLVM_GOIF_TERMINATOR
#else
#  define KLEE_LLVM_GOIF_TERMINATOR , NULL
#endif

#endif
