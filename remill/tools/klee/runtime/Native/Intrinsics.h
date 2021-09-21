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

extern "C" {
__attribute__((format(printf, 1, 2)))
void __kleemill_strace(const char *format, ...) {
 if (auto fp = stdout) {
   va_list args;
   va_start(args, format);
   vfprintf(fp, format, args);
   va_end(args);
  }
}

// kleemill functions are implemented and handled through klee's special function handler

Memory *__kleemill_at_error(State &state, addr_t ret_addr, Memory *memory);
Memory *__kleemill_at_unhandled_hypercall(State &state, addr_t ret_addr, Memory *memory);

typedef Memory * (LiftedFunc)(State &, addr_t, Memory *);
LiftedFunc *__kleemill_get_lifted_function(Memory *, addr_t pc);

bool __kleemill_can_write_byte(Memory *memory, addr_t addr);

bool __kleemill_can_read_byte(Memory *memory, addr_t addr);

Memory *__kleemill_free_memory(Memory *memory,
        addr_t where, addr_t size);

Memory *__kleemill_allocate_memory(
    Memory *memory, addr_t where, addr_t size,
    const char *name, uint64_t offset);

Memory *__kleemill_protect_memory(
    Memory *memory, addr_t where, addr_t size, bool can_read,
    bool can_write, bool can_exec);

bool kleemill_is_mapped_address(Memory * memory, addr_t where);

uint64_t kleemill_find_unmapped_address(
    Memory *memory, uint64_t base, uint64_t limit, uint64_t size);

// Returns true if the memory at address `addr` is readable.
[[gnu::used, gnu::const]]
extern bool __kleemill_can_read_byte(Memory *memory, addr_t addr);

// Returns true if the memory at address `addr` is writable.
[[gnu::used, gnu::const]]
extern bool __kleemill_can_write_byte(Memory *memory, addr_t addr);

extern Memory *__kleemill_allocate_memory(Memory *memory, addr_t where,
                                       addr_t size, const char *name,
                                       uint64_t offset);

extern Memory *__kleemill_free_memory(Memory *memory, addr_t where, addr_t size);

extern Memory *__kleemill_protect_memory(Memory *memory, addr_t where,
                                      addr_t size, bool can_read,
                                      bool can_write, bool can_exec);

extern bool __kleemill_is_mapped_address(Memory *memory, addr_t where);

extern void __kleemill_log_state(State *state);

// Finds some unmapped memory.
addr_t __kleemill_find_unmapped_address(Memory *memory, addr_t base,
                                     addr_t limit, addr_t size);
} // extern C

size_t NumReadableBytes(Memory *memory, addr_t addr, size_t size);
size_t NumWritableBytes(Memory *memory, addr_t addr, size_t size);

inline static bool CanReadMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumReadableBytes(memory, addr, size);
}

inline static bool CanWriteMemory(Memory *memory, addr_t addr, size_t size) {
  return size == NumWritableBytes(memory, addr, size);
}

Memory *CopyToMemory(Memory *memory, addr_t addr,
                     const void *data, size_t size);

void CopyFromMemory(Memory *memory, void *data, addr_t addr, size_t size);

template <typename T>
inline static T ReadMemory(Memory *memory, addr_t addr) {
  T val{};
  CopyFromMemory(memory, &val, addr, sizeof(T));
  return val;
}

template <typename T>
inline static bool TryReadMemory(Memory *memory, addr_t addr, T *val) {
  if (CanReadMemory(memory, addr, sizeof(T))) {
    CopyFromMemory(memory, val, addr, sizeof(T));
    return true;
  } else {
    return false;
  }
}

// You don't want to be using this function, it doesn't make sense to copy a
// pointer into an emulated address space.
template <typename T>
inline static bool TryWriteMemory(Memory *&, addr_t, const T *) {
  abort();
}

template <typename T>
inline static bool TryWriteMemory(Memory *&memory, addr_t addr, const T &val) {
  if (CanWriteMemory(memory, addr, sizeof(T))) {
    memory = CopyToMemory(memory, addr, &val, sizeof(T));
    return true;
  } else {
    return false;
  }
}



size_t CopyStringFromMemory(Memory *memory, addr_t addr,
                            char *val, size_t max_len);

size_t CopyStringToMemory(Memory *memory, addr_t addr, const char *val,
                          size_t len);

inline static addr_t AlignToPage(addr_t addr) {
  return addr & ~4095UL;
}

inline static addr_t AlignToNextPage(addr_t addr) {
  return (addr + 4095UL) & ~4095UL;
}



#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#if 1
# define STRACE_SYSCALL_NUM(nr) \
   do { \
     __kleemill_strace( \
         ANSI_COLOR_YELLOW "%3" PRIuADDR ":" ANSI_COLOR_RESET, \
         nr); \
   } while (false)

# define STRACE_ERROR(syscall, fmt, ...) \
   __kleemill_strace(ANSI_COLOR_RED #syscall ":" fmt ANSI_COLOR_RESET "\n", \
                  ##__VA_ARGS__)

# define STRACE_SUCCESS(syscall, fmt, ...) \
   __kleemill_strace(ANSI_COLOR_GREEN #syscall ":" fmt ANSI_COLOR_RESET "\n", \
                  ##__VA_ARGS__)
#else
# define STRACE_SYSCALL_NUM(...)
# define STRACE_ERROR(...)
# define STRACE_SUCCESS(...)
#endif

