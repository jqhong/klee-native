/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#include <fcntl.h>

#include <sstream>
#include <iostream>

#include "remill/OS/FileSystem.h"

#include "Native/Memory/AddressSpace.h"
#include "Native/Memory/Snapshot.h"
#include "Native/Workspace/Workspace.h"

#include "Native/Arch/Arch.h"
#include "remill/Arch/Arch.h"

#ifndef KLEE_NATIVE_BUILD_RUNTIME_DIR
# error "`KLEE_NATIVE_BUILD_RUNTIME_DIR` must be set."
# define KLEE_NATIVE_BUILD_RUNTIME_DIR ""
#endif  // KLEE_NATIVE_BUILD_RUNTIME_DIR

#ifndef KLEE_NATIVE_INSTALL_RUNTIME_DIR
# error "`KLEE_NATIVE_INSTALL_RUNTIME_DIR` must be defined."
# define KLEE_NATIVE_INSTALL_RUNTIME_DIR ""
#endif  // KLEE_NATIVE_INSTALL_RUNTIME_DIR

#ifndef KLEE_NATIVE_SOURCE_DIR
# error "`KLEE_NATIVE_SOURCE_DIR` must be defined."
# define KLEE_NATIVE_SOURCE_DIR ""
#endif  // KLEE_NATIVE_SOURCE_DIR

DEFINE_string(workspace_dir, ".",
    "Path to workspace in which the snapshot file is"
        " stored, and in which files will be placed.");

DEFINE_string(runtime, "", "Name of a runtime, or absolute path to a "
    "runtime bitcode file.");

DECLARE_string (arch);
DECLARE_string (os);

namespace klee {
namespace native {

const std::string &Workspace::Dir(void) {
  static std::string path;
  if (path.empty()) {
    if (FLAGS_workspace_dir.empty()) {
      path = remill::CurrentWorkingDirectory();
    } else {
      path = FLAGS_workspace_dir;
    }
    path = remill::CanonicalPath(path);
    CHECK(remill::TryCreateDirectory(path))<< "Could not create workspace directory " << path;
  }
  return path;
}


const std::string &Workspace::PreLiftedTraces(void) {
  static std::string path;
  std::stringstream ss;
  ss << klee::native::Workspace::Dir() << "/prelift_traces/";
  path = ss.str();
  return path;
}


const std::string &Workspace::FormatTraceRange(uint64_t start, uint64_t end) {
  static std::string path;
  std::stringstream ss;
  ss << PreLiftedTraces() << "/0x" << std::hex << start
      << std::dec << "-0x" << std::hex << end << std::dec;
  //LOG(INFO) << "map file is " << ss.str();
  path = ss.str();
  return path;
}

const std::string &Workspace::SnapshotPath(void) {
  static std::string path;
  if (path.empty()) {
    std::stringstream ss;
    ss << Dir() << remill::PathSeparator() << "snapshot";
    path = ss.str();
    path = remill::CanonicalPath(path);
  }
  return path;
}


const std::string &Workspace::BitcodeCachePath(void) {
  static std::string path;
  if (path.empty()) {
    std::stringstream ss;
    ss << Dir() << remill::PathSeparator() << "bitcode_cache";
    path = ss.str();
    path = remill::CanonicalPath(path);
  }
  return path;
}


const std::string &Workspace::IndexPath(void) {
  static std::string path;
  if (path.empty()) {
    std::stringstream ss;
    ss << Dir() << remill::PathSeparator() << "index";
    path = ss.str();
    path = remill::CanonicalPath(path);
  }
  return path;
}

const std::string &Workspace::MemoryDir(void) {
  static std::string path;
  if (path.empty()) {
    std::stringstream ss;
    ss << Dir() << remill::PathSeparator() << "memory";
    path = ss.str();
    path = remill::CanonicalPath(path);
    CHECK(remill::TryCreateDirectory(path))<< "Could not create memory directory " << path;
  }
  return path;
}

const std::string &Workspace::BitcodeDir(void) {
  static std::string path;
  if (path.empty()) {
    std::stringstream ss;
    ss << Dir() << remill::PathSeparator() << "bitcode";
    path = ss.str();
    path = remill::CanonicalPath(path);
    CHECK(remill::TryCreateDirectory(path))<< "Could not create bitcode directory " << path;
  }
  return path;
}

static std::string gBuildRuntimDir = KLEE_NATIVE_BUILD_RUNTIME_DIR;
static std::string gInstallRuntimeDir = KLEE_NATIVE_INSTALL_RUNTIME_DIR;
static std::string gSourceDir = KLEE_NATIVE_SOURCE_DIR;

const std::string &Workspace::LocalRuntimeBitcodePath(void) {
  static std::string path;
  if (!path.empty()) {
    return path;
  }

  if (FLAGS_runtime.empty()) {
    FLAGS_runtime = FLAGS_os + "_" + FLAGS_arch;
  }

  path = Dir() + remill::PathSeparator() + FLAGS_runtime + ".bc";
  return path;
}

const std::string &Workspace::RuntimeBitcodePath(void) {
  static std::string path;
  if (!path.empty()) {
    return path;
  }

  std::string search_paths[] = {
      "",  // If it's an absolute path.
      remill::CurrentWorkingDirectory() + remill::PathSeparator(), Dir()
          + remill::PathSeparator(), gBuildRuntimDir + remill::PathSeparator(),
      gInstallRuntimeDir + remill::PathSeparator(), };

  if (FLAGS_runtime.empty()) {
    FLAGS_runtime = FLAGS_os + "_" + FLAGS_arch;
  }

  for (auto runtime_dir : search_paths) {
    std::stringstream ss;
    ss << runtime_dir << FLAGS_runtime;
    path = ss.str();
    path = remill::CanonicalPath(path);
    if (remill::FileExists(path)) {
      return path;
    }

    path += ".bc";
    if (remill::FileExists(path)) {
      return path;
    }
  }

  LOG(FATAL) << "Cannot find path to runtime for " << FLAGS_os << " and "
      << FLAGS_arch;

  path.clear();
  return path;
}

const std::string &Workspace::RuntimeInterceptPath(void) {
  static std::string path;
  std::stringstream ss;
  std::string intercept = "libruntime-intercepts.so";
  ss << gBuildRuntimDir << intercept;
  path = ss.str();
  return path;
}

const std::string &Workspace::BinjaScriptPath(void) {
  static std::string path;
  std::stringstream ss;
  ss << gSourceDir << "/scripts/locate_traces.py";
  path = ss.str();
  return path;
}

const std::string &Workspace::TraceListPath(void) {
  static std::string path;
  std::stringstream ss;
  ss << Workspace::Dir() << "/trace_list";
  path = ss.str();
  return path;
}

namespace {

using AddressSpaceIdToMemoryMap =
std::unordered_map<int64_t, std::shared_ptr<AddressSpace>>;

// Load in the data from the snapshotted page range into the address space.
static void LoadPageRangeFromFile(AddressSpace *addr_space,
    const snapshot::PageRange &range) {
  std::stringstream ss;
  ss << Workspace::MemoryDir() << remill::PathSeparator() << range.name();

  auto path = ss.str();
  CHECK(remill::FileExists(path))<< "File " << path << " with the data of the page range ["
  << std::hex << range.base() << ", " << std::hex << range.limit()
  << ") does not exist.";

  auto range_size = static_cast<uint64_t>(range.limit() - range.base());
  CHECK_LE(range_size, remill::FileSize(path)) << "File " << path
      << " with the data of the page range [" << std::hex << range.base()
      << ", " << std::hex << range.limit() << std::dec << ") is too small.";

  LOG(INFO) << "Loading file " << path << " into range [" << std::hex
      << range.base() << ", " << range.limit() << ")" << std::dec;

  auto fd = open(path.c_str(), O_RDONLY);

  // Read bytes from the file into the address space.
  uint64_t base_addr = static_cast<uint64_t>(range.base());

  while (range_size) {
    auto buff = addr_space->ToReadWriteVirtualAddress(base_addr);

    errno = 0;
    auto amount_read_ = read(fd, buff, range_size);
    auto err = errno;
    if (-1 == amount_read_) {
      CHECK(!range_size)<< "Failed to read all page range data from " << path
      << "; remaining amount to read is " << range_size
      << " but got error " << strerror(err);
      break;
    }

    auto amount_read = static_cast<uint64_t>(amount_read_);
    base_addr += amount_read;
    range_size -= amount_read;
  }

  close(fd);
}

// Go through the snapshotted pages and copy them into the address space.
static void LoadAddressSpaceFromSnapshot(
    AddressSpaceIdToMemoryMap &addr_space_ids,
    const snapshot::AddressSpace &orig_addr_space) {

  LOG(INFO) << "Initializing address space " << orig_addr_space.id();

  auto id = orig_addr_space.id();
  CHECK(!addr_space_ids.count(id))<< "Address space " << std::dec << orig_addr_space.id()
  << " has already been deserialized.";

  std::shared_ptr<AddressSpace> emu_addr_space;

  // Create the address space, either as a clone of a parent, or as a new one.
  if (orig_addr_space.has_parent_id()) {
    int64_t parent_id = orig_addr_space.parent_id();
    CHECK(addr_space_ids.count(parent_id))<< "Cannot find parent address space " << std::dec << parent_id
    << " for address space " << std::dec << orig_addr_space.id();

    const auto &parent_mem = addr_space_ids[parent_id];
    emu_addr_space = std::make_shared<AddressSpace>(*parent_mem);
  } else {
    emu_addr_space = std::make_shared<AddressSpace>();
  }

  addr_space_ids[id] = emu_addr_space;

  // Bring in the ranges.
  for (const auto &page : orig_addr_space.page_ranges()) {
    CHECK(page.limit() > page.base())<<"Invalid page map information with base " << std::hex << page.base()
    << " being greater than or equal to the page limit " << page.limit()
    << " in address space " << std::dec
    << orig_addr_space.id();

    const char *path = nullptr;
    switch (page.kind()) {
      case snapshot::kLinuxStackPageRange:
      path = "[stack]";
      break;
      case snapshot::kLinuxHeapPageRange:
      path = "[heap]";
      break;
      case snapshot::kLinuxVVarPageRange:
      path = "[vvar]";
      break;
      case snapshot::kLinuxVDSOPageRange:
      path = "[vdso]";
      break;
      case snapshot::kLinuxVSysCallPageRange:
      path = "[vsyscall]";
      break;
      case snapshot::kFileBackedPageRange:
      if (page.has_file_path()) {
        path = page.file_path().c_str();
      } else {
        LOG(ERROR)
        << "Page map with base " << std::hex << page.base() << " and limit "
        << page.limit() << " in address space " << std::dec
        << orig_addr_space.id() << " is file-backed, but does not have "
        << "a file path.";
      }
      break;
      case snapshot::kAnonymousPageRange:
      case snapshot::kAnonymousZeroRange:
      break;
    }

    auto base = static_cast<uint64_t>(page.base());
    auto limit = static_cast<uint64_t>(page.limit());
    auto size = limit - base;
    auto offset = static_cast<uint64_t>(
        page.has_file_offset() ? page.file_offset() : 0L);
    emu_addr_space->AddMap(base, size, path, offset);
    if (snapshot::kAnonymousZeroRange != page.kind()) {
      LoadPageRangeFromFile(emu_addr_space.get(), page);
    }

    emu_addr_space->SetPermissions(base, size, page.can_read(),
        page.can_write(), page.can_exec());
  }
}

}
  // namespace

void Workspace::LoadSnapshotIntoExecutor(const ProgramSnapshotPtr &snapshot,
  klee::Interpreter *executor) {

LOG(INFO) << "Loading address space information from snapshot";

AddressSpaceIdToMemoryMap address_space_ids;
for (const auto &address_space : snapshot->address_spaces()) {
  LoadAddressSpaceFromSnapshot(address_space_ids, address_space);
}

LOG(INFO) << "Loading task information.";
for (const auto &task : snapshot->tasks()) {
  int64_t addr_space_id = task.address_space_id();
  CHECK(address_space_ids.count(addr_space_id))<< "Invalid address space id " << std::dec << addr_space_id
    << " for task";

  auto memory = address_space_ids[addr_space_id];
  auto pc = static_cast<uint64_t>(task.pc());

  LOG(INFO) << "Adding task starting execution at " << std::hex << pc
      << " in address space " << std::dec << addr_space_id;

  executor->AddInitialTask(task.state(), pc, memory);
}
}

}
  // namespace native
} // namespace klee
