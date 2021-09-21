/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <string>
#include "klee/Interpreter.h"

namespace klee {
namespace native {

class ProgramSnapshotPtr;

class Workspace {
 public:
  static const std::string &Dir(void);
  static const std::string &SnapshotPath(void);
  static const std::string &IndexPath(void);
  static const std::string &MemoryDir(void);
  static const std::string &BitcodeDir(void);
  static const std::string &LocalRuntimeBitcodePath(void);
  static const std::string &RuntimeBitcodePath(void);
  static const std::string &RuntimeInterceptPath(void);
  static const std::string &BitcodeCachePath(void);
  static const std::string &BinjaScriptPath(void);
  static const std::string &TraceListPath(void);
  static const std::string &PreLiftedTraces(void);
  static const std::string &FormatTraceRange(uint64_t start, uint64_t end);

  static void LoadSnapshotIntoExecutor(
      const ProgramSnapshotPtr &snapshot, klee::Interpreter *executor);

 private:
  Workspace(void) = delete;
};

}  // namespace native
}  // namespace klee
