#ifndef KLEE_CONFIG_CONFIG_H
#define KLEE_CONFIG_CONFIG_H

/* Using Z3 Solver backend */
#define ENABLE_Z3 1

#define HAVE_SYS_CAPABILITY_H 1

/* LLVM major version number */
//#define LLVM_VERSION_MAJOR 7

/* klee-uclibc is supported */
#define SUPPORT_KLEE_UCLIBC 1

#define  HAVE_Z3_GET_ERROR_MSG_NEEDS_CONTEXT 1

/* Configuration type of KLEE's runtime libraries */
#define RUNTIME_CONFIGURATION "Release+Debug+Asserts"

#include "remill/BC/Version.h"

#endif
