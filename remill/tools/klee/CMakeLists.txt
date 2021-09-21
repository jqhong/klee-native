# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(kleemill)
cmake_minimum_required(VERSION 3.2)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

#FindAndSelectClangCompiler()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

set(KLEEMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")

# warnings and compiler settings
if(NOT DEFINED WIN32)
  #set(PROJECT_CXXFLAGS
  #  ${GLOBAL_CXXFLAGS} -pedantic  -Werror -Wno-conversion -Wno-shorten-64-to-32 -Wno-sign-compare -Wno-unused-value
  #  -Wno-unreachable-code-return 
  #)
endif()

# protobuf
find_package(Protobuf REQUIRED)
list(APPEND PROJECT_LIBRARIES ${Protobuf_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Protobuf_INCLUDE_DIR})

list(APPEND PROJECT_DEFINITIONS "GOOGLE_PROTOBUF_NO_RTTI")

#
# protobuf file generation 
#
 
# this function can't be told where to store the output files! we have to add the whole binary directory
# to the include directories (or change it and lose compatibility with the system libraries)
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES PROJECT_PROTOBUFHEADERFILES
                      "${KLEEMILL_SOURCE_DIR}/lib/Native/Memory/Snapshot.proto")

list(APPEND PROJECT_INCLUDEDIRECTORIES ${PROJECT_PROTOBUFHEADERFILES})
list(APPEND PROJECT_INCLUDEDIRECTORIES "${KLEEMILL_SOURCE_DIR}/lib")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${KLEEMILL_SOURCE_DIR}/include")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}")
list(APPEND PROJECT_INCLUDEDIRECTORIES "${KLEEMILL_SOURCE_DIR}/third_party")


# disable -Werror on these file since they have been generated
set_source_files_properties(${PROJECT_PROTOBUFSOURCEFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")
set_source_files_properties(${PROJECT_PROTOBUFHEADERFILES} PROPERTIES COMPILE_FLAGS "-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-conversion")

set(KLEEMILL klee-exec-${REMILL_LLVM_VERSION})

list(APPEND PROJECT_DEFINITIONS "KLEE_NATIVE_INSTALL_RUNTIME_DIR=\"${CMAKE_INSTALL_PREFIX}/share/kleemill/${REMILL_LLVM_VERSION}/runtime/\"")
list(APPEND PROJECT_DEFINITIONS "KLEE_NATIVE_BUILD_RUNTIME_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/runtime/\"")
list(APPEND PROJECT_DEFINITIONS "KLEE_NATIVE_SOURCE_DIR=\"${KLEEMILL_SOURCE_DIR}\"")

add_library(${PROJECT_NAME} STATIC
  ${PROJECT_PROTOBUFSOURCEFILES}
  lib/Basic/CmdLineOptions.cpp
  lib/Basic/ConstructSolverChain.cpp
  lib/Basic/KTest.cpp
  lib/Basic/Statistics.cpp

  lib/Core/AddressSpace.cpp
  lib/Core/MergeHandler.cpp
  lib/Core/CallPathManager.cpp
  lib/Core/Context.cpp
  lib/Core/CoreStats.cpp
  lib/Core/ExecutionState.cpp
  lib/Core/Executor.cpp
  lib/Core/ExecutorTimers.cpp
  lib/Core/ExecutorUtil.cpp
  lib/Core/ExternalDispatcher.cpp
  lib/Core/ImpliedValue.cpp
  lib/Core/Memory.cpp
  lib/Core/MemoryManager.cpp
  lib/Core/PTree.cpp
  lib/Core/Searcher.cpp
  lib/Core/SeedInfo.cpp
  lib/Core/SpecialFunctionHandler.cpp
  lib/Core/StatsTracker.cpp
  lib/Core/TimingSolver.cpp
  lib/Core/UserSearcher.cpp
  lib/Core/Continuation.cpp
  lib/Core/PreLifter.cpp
  
  lib/Expr/ArrayCache.cpp
  lib/Expr/ArrayExprOptimizer.cpp
  lib/Expr/ArrayExprRewriter.cpp
  lib/Expr/ArrayExprVisitor.cpp
  lib/Expr/Assigment.cpp
  lib/Expr/AssignmentGenerator.cpp
  lib/Expr/Constraints.cpp
  lib/Expr/ExprBuilder.cpp
  lib/Expr/Expr.cpp
  lib/Expr/ExprEvaluator.cpp
  lib/Expr/ExprPPrinter.cpp
  lib/Expr/ExprSMTLIBPrinter.cpp
  lib/Expr/ExprUtil.cpp
  lib/Expr/ExprVisitor.cpp
  lib/Expr/Lexer.cpp
  lib/Expr/Parser.cpp
  lib/Expr/Updates.cpp
  
  lib/Module/Checks.cpp
  lib/Module/InstructionInfoTable.cpp
  lib/Module/InstructionOperandTypeCheckPass.cpp
  lib/Module/IntrinsicCleaner.cpp
  lib/Module/KInstruction.cpp
  lib/Module/KModule.cpp
  lib/Module/LowerSwitch.cpp
  lib/Module/ModuleUtil.cpp
  lib/Module/Optimize.cpp
  lib/Module/PhiCleaner.cpp
  lib/Module/RaiseAsm.cpp

  lib/Solver/AssignmentValidatingSolver.cpp
  lib/Solver/CachingSolver.cpp
  lib/Solver/CexCachingSolver.cpp
  lib/Solver/ConstantDivision.cpp
  lib/Solver/CoreSolver.cpp
  lib/Solver/DummySolver.cpp
  lib/Solver/FastCexSolver.cpp
  lib/Solver/IncompleteSolver.cpp
  lib/Solver/IndependentSolver.cpp
  lib/Solver/MetaSMTSolver.cpp
  lib/Solver/KQueryLoggingSolver.cpp
  lib/Solver/QueryLoggingSolver.cpp
  lib/Solver/SMTLIBLoggingSolver.cpp
  lib/Solver/Solver.cpp
  lib/Solver/SolverImpl.cpp
  lib/Solver/SolverStats.cpp
  lib/Solver/STPBuilder.cpp
  lib/Solver/STPSolver.cpp
  lib/Solver/ValidatingSolver.cpp
  lib/Solver/Z3Builder.cpp
  lib/Solver/Z3Solver.cpp
  
  lib/Support/CompressionStream.cpp
  lib/Support/ErrorHandling.cpp
  lib/Support/FileHandling.cpp
  lib/Support/MemoryUsage.cpp
  lib/Support/RNG.cpp
  lib/Support/Time.cpp
  lib/Support/Timer.cpp
  lib/Support/TreeStream.cpp

  lib/Native/Arch/Arch.cpp
  lib/Native/Arch/X86/Log.cpp
  lib/Native/Arch/AArch64/Log.cpp
  lib/Native/Arch/TraceManager.cpp
  lib/Native/Arch/BitCodeCache.cpp
  lib/Native/Memory/AddressSpace.cpp
  lib/Native/Memory/MappedRange.cpp
  lib/Native/Memory/Snapshot.cpp
  lib/Native/Memory/AllocList.cpp
  lib/Native/Memory/PolicyHandler.cpp
  lib/Native/Util/AreaAllocator.cpp
  lib/Native/Util/ZoneAllocator.cpp
  lib/Native/Workspace/Workspace.cpp

  lib/Module/OptNone.cpp
  third_party/sqlite/shell.c
  third_party/sqlite/sqlite3.c
  third_party/ThreadPool/ThreadPool.cpp
)


# remill
if(NOT TARGET remill)
  if("${PLATFORM_NAME}" STREQUAL "windows")
    set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
  endif()

  find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
endif()

list(APPEND PROJECT_LIBRARIES remill)

# llvm
find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

# Jiaqi #
# set(LLVM_LIBRARIES LLVMCodeGen LLVMAsmPrinter LLVMRuntimeDyld LLVMExecutionEngine LLVMMCJIT LLVMTarget LLVMX86AsmParser LLVMX86AsmPrinter LLVMX86CodeGen LLVMAArch64AsmParser LLVMAArch64AsmPrinter LLVMAArch64CodeGen LLVMSparcAsmParser LLVMSparcAsmPrinter LLVMSparcCodeGen dl)
set(LLVM_LIBRARIES LLVMCodeGen LLVMAsmPrinter LLVMRuntimeDyld LLVMExecutionEngine LLVMMCJIT LLVMTarget LLVMX86AsmParser LLVMX86CodeGen LLVMAArch64AsmParser LLVMAArch64CodeGen LLVMSparcAsmParser LLVMSparcCodeGen dl)
# #Jiaqi #
list(APPEND PROJECT_LIBRARIES ${LLVM_LIBRARIES})
list(APPEND PROJECT_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

# xed
find_package(XED REQUIRED)
list(APPEND PROJECT_LIBRARIES ${XED_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${XED_INCLUDE_DIRS})

# google log module
find_package(glog REQUIRED)
list(APPEND PROJECT_LIBRARIES glog::glog)

# gflags
find_package(gflags REQUIRED)
list(APPEND PROJECT_LIBRARIES gflags)

# z3
find_package(Z3 REQUIRED)
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Z3_INCLUDE_DIRS})
list(APPEND PROJECT_LIBRARIES ${Z3_LIBRARIES})

#
# target settings
#

# Jiaqi #
# list(APPEND PROJECT_LIBRARIES "/home/jqhong/Documents/glibc-2.27/build-glibc/")
# #Jiaqi#
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
target_compile_options(${PROJECT_NAME} PRIVATE ${PROJECT_CXXFLAGS})

list(APPEND PROJECT_LIBRARIES ${PROJECT_NAME})

add_executable(${KLEEMILL}
  lib/Native/Execute.cpp
)
# Jiaqi #
# target_link_libraries(${KLEEMILL} PRIVATE -Wl,-dynamic-linker,/home/jqhong/Documents/glibc-2.27/build-glibc/elf/ld-linux-x86-64.so.2)
target_link_libraries(${KLEEMILL} PRIVATE -pie)
#target_link_libraries(${KLEEMILL} PRIVATE -Wl,-rpath,/home/jqhong/Documents/glibc-2.27/build-glibc/)
# set_property(TARGET ${KLEEMILL} PROPERTY POSITION_INDEPENDENT_CODE TRUE)
# set_property(TARGET ${KLEEMILL} PROPERTY LINK_FLAGS -Wl,--dynamic-linker=/home/jqhong/Documents/glibc-2.27/build-glibc/elf/ld.so)
# #Jiaqi #

target_link_libraries(${KLEEMILL} PRIVATE ${PROJECT_LIBRARIES})
target_include_directories(${KLEEMILL} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${KLEEMILL} PUBLIC ${PROJECT_DEFINITIONS})
target_compile_options(${KLEEMILL} PRIVATE ${PROJECT_CXXFLAGS})

add_subdirectory(runtime)

if(NOT APPLE)
  set(KLEEMILL_SNAPSHOT klee-snapshot-${REMILL_LLVM_VERSION})
 
  add_executable(${KLEEMILL_SNAPSHOT}
    lib/Native/Snapshot.cpp
    lib/Native/Arch/X86/Snapshot.cpp
    lib/Native/Arch/AArch64/Snapshot.cpp
  )

  target_link_libraries(${KLEEMILL_SNAPSHOT} PRIVATE ${PROJECT_LIBRARIES})
  target_include_directories(${KLEEMILL_SNAPSHOT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
  target_compile_definitions(${KLEEMILL_SNAPSHOT} PUBLIC ${PROJECT_DEFINITIONS})
  target_compile_options(${KLEEMILL_SNAPSHOT} PRIVATE ${PROJECT_CXXFLAGS})
endif()
