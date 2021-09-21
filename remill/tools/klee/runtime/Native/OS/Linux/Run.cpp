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

#ifndef KLEEMILL_RUNTIME_LINUX_RUN_CPP_
#define KLEEMILL_RUNTIME_LINUX_RUN_CPP_

namespace {

static linux_task *gTaskList = nullptr;
static linux_task *gLastTask = nullptr;

}  // namespace

static pid_t gNextTid = kProcessId;

// Initialize klee's concrete remill AddressSpace
extern "C" void klee_init_remill_memory(Memory *mem);

// Initialize the emulated Linux operating system.
extern "C" void __kleemill_init(Memory *mem) {
  gNextTid = kProcessId;
  gTaskList = nullptr;
  gLastTask = nullptr;
  klee_init_remill_memory(mem);
  //klee_init_fds(0,0,20,0,1,0);
}

// Tear down the emulated Linux operating system.
extern "C" void __kleemill_fini(void) {
  linux_task *next_task = nullptr;
  for (auto task = gTaskList; task; task = next_task) {
    next_task = task->next;
    task->next = nullptr;
    task->next_circular = nullptr;

    delete task;
  }

  gTaskList = nullptr;
  gLastTask = nullptr;
}

// adds new OS task
extern "C" linux_task *__kleemill_create_task(State *state,
                                              Memory *memory) {
  auto task = new linux_task;
  memset(task, 0, sizeof(task));
  memcpy(&(task->state), state, sizeof(State));
  task->time_stamp_counter = 0;
  task->status = kTaskStatusRunnable;
  task->location = kTaskStoppedAtSnapshotEntryPoint;
  task->tid = gNextTid++;
  task->memory = memory;
  task->last_pc = CurrentPC(task->state);
  task->continuation = __kleemill_get_lifted_function(memory, task->last_pc);
  task->blocked_count = 0;
  task->wake_count = 0;

  task->next = gTaskList;
  task->next_circular = gTaskList;

  if (!gTaskList) {
    gLastTask = task;
  }

  gTaskList = task;
  gLastTask->next_circular = task;

  return task;
}

// Called by the executor when all initial tasks are loaded.
extern "C" void __kleemill_schedule(void) {
  for (auto progressed = true; progressed; ) {
    progressed = false;
    for (auto task = gTaskList; task; task = task->next) {
       switch (task->status) {

        case kTaskStatusResumable:
          if (task->blocked_count) {
            task->blocked_count--;
            break;
          } else {
            task->status = kTaskStatusRunnable;
          }
          [[clang::fallthrough]];

        case kTaskStatusRunnable:
          progressed = true;
          if (task->blocked_count) {
            puts("Cannot have a runnable task with non-zero blocked count\n");
            abort();
          }

          gCurrent = task;
          //puts("executing");
          task->continuation(task->state, task->last_pc, task->memory);
          gCurrent = nullptr;
          break;

        default:
          printf("Task status %p = %" PRIx64 "\n",
                 reinterpret_cast<void *>(&(task->status)), task->status);
          break;
      }
    }

    // Unblock any blocked tasks. This will count down all `blocked_count`s
    // until at least one of them becomes unblocked.
    for (auto try_again = true; try_again && !progressed; ) {
      try_again = false;
      for (auto task = gTaskList; task; task = task->next) {

        if (kTaskStatusResumable == task->status || task->status == kTaskStatusRunnable) {
          if (task->blocked_count) {
            task->blocked_count--;
            try_again = true;

          } else {
            task->status = kTaskStatusRunnable;
            progressed = true;
          }
        }
      }
    }
  }
}

#endif  // KLEEMILL_RUNTIME_LINUX_RUN_CPP_
