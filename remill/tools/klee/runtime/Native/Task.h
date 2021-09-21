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

#pragma once

#include <cstdint>

#include "Intrinsics.h"

struct ArchState;
struct Memory;

enum TaskStatus : uint64_t {
  // This task is ready to run.
  kTaskStatusRunnable,

  // This task is paused doing async I/O. This is a runnable state.
  kTaskStatusResumable,

  // This task encountered an error.
  kTaskStatusError,

  // This task exited.
  kTaskStatusExited,
};

enum TaskStopLocation : uint64_t {
  kTaskNotYetStarted,
  kTaskStoppedAtSnapshotEntryPoint,
  kTaskStoppedAtJumpTarget,
  kTaskStoppedAtCallTarget,
  kTaskStoppedAtReturnTarget,
  kTaskStoppedAtError,
  kTaskStoppedBeforeHyperCall,
  kTaskStoppedAfterHyperCall,
  kTaskStoppedBeforeUnhandledHyperCall,
  kTaskStoppedAtUnsupportedInstruction,
  kTaskStoppedAtExit,
  kTaskStoppedAtMissingBlock,
};

inline static bool CanContinue(TaskStopLocation loc) {
  switch (loc) {
    case kTaskStoppedAtError: return false;
    case kTaskStoppedBeforeUnhandledHyperCall: return false;
    case kTaskStoppedAtUnsupportedInstruction: return false;
    case kTaskStoppedAtExit: return false;
    default: return true;
  }
}

enum MemoryAccessFaultKind : uint16_t {
  kMemoryAccessNoFault,
  kMemoryAccessFaultOnRead,
  kMemoryAccessFaultOnWrite,
  kMemoryAccessFaultOnExecute
};

enum MemoryValueType : uint16_t {
  kMemoryValueTypeInvalid,
  kMemoryValueTypeInteger,
  kMemoryValueTypeFloatingPoint,
  kMemoryValueTypeInstruction
};

struct Task {
  State state;
  uint64_t time_stamp_counter;
  LiftedFunc *continuation;
  TaskStatus status;
  TaskStopLocation location;
  addr_t last_pc;
};

extern Task *gCurrent;

