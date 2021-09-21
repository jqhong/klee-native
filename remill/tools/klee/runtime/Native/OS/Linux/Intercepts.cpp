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
#include "runtime/Native/Intrinsics.h"
namespace {


extern "C" {
long strtol_intercept(addr_t nptr, addr_t endptr, int base, Memory *memory);
addr_t malloc_intercept( Memory *memory, uint64_t size);
bool free_intercept( Memory *memory, addr_t ptr);
addr_t calloc_intercept( Memory *memory, uint64_t size);
addr_t realloc_intercept( Memory *memory, addr_t ptr,  uint64_t size);
size_t malloc_size( Memory *memory, addr_t ptr);
addr_t memset_intercept(Memory * memory, addr_t s, int c, size_t n);
addr_t memcpy_intercept(Memory * memory, addr_t dest, addr_t src, size_t n);
addr_t memmove_intercept(Memory * memory, addr_t dest, addr_t src, size_t n);
addr_t strcpy_intercept(Memory *memory, addr_t dest, addr_t src);
addr_t strncpy_intercept(Memory *memory, addr_t dest, addr_t src, size_t n);
size_t strlen_intercept(Memory *memory, addr_t s);
size_t strnlen_intercept(Memory *memory, addr_t s, size_t n);
}  // extern C

template <typename ABI>
static Memory *Intercept_strtol(Memory *memory, State *state,
                                const ABI &intercept) {
  addr_t nptr = 0;
  addr_t endptr = 0;
  int base = 0;

  if (!intercept.TryGetArgs(memory, state, &nptr, &endptr, &base)) {
    STRACE_ERROR(libc_strtol, "Couldn't get args");
    exit(1);
  }

  long number = strtol_intercept(nptr, endptr, base, memory);

  exit(0);
}


static constexpr addr_t kBadAddr = ~0ULL;

static constexpr addr_t kReallocInternalPtr = ~0ULL - 1ULL;
static constexpr addr_t kReallocTooBig = ~0ULL - 2ULL;
static constexpr addr_t kReallocInvalidPtr = ~0ULL - 3ULL;
static constexpr addr_t kReallocFreedPtr = ~0ULL - 4ULL;

static constexpr addr_t kMallocTooBig = ~0ULL - 1ULL;

template <typename ABI>
static Memory *Intercept_malloc(Memory *memory, State *state,
                                const ABI &intercept) {
  addr_t alloc_size = 0;
  if (!intercept.TryGetArgs(memory, state, &alloc_size)) {
    STRACE_ERROR(malloc, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  if (!alloc_size) {
    STRACE_SUCCESS(libc_malloc, "size=0, ptr=0");
    return intercept.SetReturn(memory, state, 0);
  }

  const auto ptr = malloc_intercept(memory, alloc_size);
  if (ptr == kBadAddr) {
    STRACE_ERROR(libc_malloc, "Falling back to real malloc for size=%" PRIxADDR,
                 alloc_size);
    return memory;

  } else if (ptr == kMallocTooBig) {
    STRACE_ERROR(libc_malloc, "Malloc for size=%" PRIxADDR " too big",
                 alloc_size);
    return memory;

  } else {
    STRACE_SUCCESS(libc_malloc, "size=%" PRIdADDR ", ptr=%" PRIxADDR,
                   alloc_size, ptr);
    return intercept.SetReturn(memory, state, ptr);
  }
}

template <typename ABI>
static Memory *Intercept_free(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t address = 0;
  if (!intercept.TryGetArgs(memory, state, &address)) {
    STRACE_ERROR(libc_free, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  if (!address) {
    STRACE_SUCCESS(libc_free, "ptr=%" PRIxADDR, address);
    return intercept.SetReturn(memory, state, 0);
  }

  if (!free_intercept(memory, address)) {
    STRACE_ERROR(libc_free, "Falling back to real free for ptr=%" PRIxADDR,
                 address);
    return memory;
  }

  STRACE_SUCCESS(libc_free, "ptr=%" PRIxADDR, address);
  return intercept.SetReturn(memory, state, 0);
}


template <typename ABI>
static Memory *Intercept_calloc(Memory *memory, State *state,
                                const ABI &intercept) {
  addr_t num = 0;
  addr_t size = 0;
  if (!intercept.TryGetArgs(memory, state, &num, &size)) {
    STRACE_ERROR(libc_calloc, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t alloc_size = num * size;
  if (!alloc_size) {
    STRACE_SUCCESS(libc_calloc, "num=%" PRIxADDR ", size=%" PRIxADDR ", ptr=0", num, size);
    return intercept.SetReturn(memory, state, 0);
  }

  const auto ptr = calloc_intercept(memory, alloc_size);
  if (ptr == kBadAddr) {
    STRACE_ERROR(libc_calloc, "Falling back to real calloc for num=%" PRIxADDR
                 ", size=%" PRIxADDR, num, size);
    return memory;

  } else if (ptr == kMallocTooBig) {
    STRACE_ERROR(libc_calloc, "Calloc for size=%" PRIxADDR " too big",
                 alloc_size);
    return memory;

  } else {
    STRACE_SUCCESS(libc_calloc, "num=%" PRIdADDR ", size=%" PRIdADDR ", ptr=%" PRIxADDR,
                   num, size, ptr);
    return intercept.SetReturn(memory, state, ptr);
  }
}

template <typename ABI>
static Memory *Intercept_realloc(Memory *memory, State *state,
                                 const ABI &intercept) {
  addr_t ptr;
  size_t alloc_size;
  if (!intercept.TryGetArgs(memory, state, &ptr, &alloc_size)) {
    STRACE_ERROR(libc_realloc, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  if (!alloc_size) {
    if (ptr && !free_intercept(memory, ptr)) {

      STRACE_ERROR(libc_realloc, "Error freeing old_ptr=%" PRIxADDR, ptr);
    }

    STRACE_SUCCESS(libc_realloc, "old_ptr=%" PRIxADDR ", new_size=%" PRIdADDR ", new_ptr=%" PRIxADDR,
                   ptr, alloc_size, 0);
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t new_ptr = realloc_intercept(memory, ptr, alloc_size);

  if (new_ptr == kBadAddr) {
    STRACE_ERROR(libc_realloc, "Falling back to real realloc for ptr=%" PRIxADDR
                 ", size=%" PRIxADDR, ptr, alloc_size);
    return memory;

  } else if (kReallocInternalPtr == new_ptr) {
    STRACE_ERROR(libc_realloc, "Can't realloc displaced malloc addr=%" PRIxADDR, ptr);
    klee_abort();

  } else if (kReallocTooBig == new_ptr) {
    STRACE_ERROR(libc_realloc, "Realloc size=%" PRIxADDR " too big", alloc_size);
    klee_abort();

  } else if (kReallocInvalidPtr == new_ptr) {
    STRACE_ERROR(libc_realloc, "Realloc on untracked addr=%" PRIxADDR, ptr);
    klee_abort();

  } else if (kReallocFreedPtr == new_ptr) {
    STRACE_ERROR(libc_realloc, "Realloc on freed addr=%" PRIxADDR, ptr);
    klee_abort();

  } else {
    STRACE_SUCCESS(libc_realloc, "old_ptr=%" PRIxADDR ", new_size=%" PRIdADDR ", new_ptr=%" PRIxADDR,
                   ptr, alloc_size, new_ptr);
    return intercept.SetReturn(memory, state, new_ptr);
  }
}

template <typename ABI>
static Memory *Intercept_memalign(Memory *memory, State *state,
                                  const ABI &intercept) {
  size_t alignment;
  size_t size;
  if (!intercept.TryGetArgs(memory, state, &alignment, &size)) {
    STRACE_ERROR(libc_memalign, "Couldn't get args");
    return intercept.SetReturn(0, state, 0);
  }
  const auto ptr = malloc_intercept(memory, size);
  if (ptr == kBadAddr) {
    STRACE_ERROR(libc_memalign, "Falling back to real memalign for align=%"
                 PRIxADDR ", size=%" PRIxADDR, alignment, size);
    return memory;
  }
  return intercept.SetReturn(memory, state, ptr);
}


template <typename ABI>
static Memory *Intercept_malloc_usable_size(Memory *memory, State *state,
                                            const ABI &intercept) {
  addr_t ptr;
  if (!intercept.TryGetArgs(memory, state, &ptr)) {
    STRACE_ERROR(read, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  const auto size = malloc_size(memory, ptr);
  if (!size) {
    STRACE_ERROR(
        libc_malloc_usable_size, "Falling back to real malloc_usable_size for ptr=%"
        PRIxADDR, ptr);
    return memory;
  }
  return intercept.SetReturn(memory, state, size);
}


template <typename ABI>
static Memory *Intercept_memset(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t s;
  int c;
  size_t n;
  if (!intercept.TryGetArgs(memory, state, &s, &c, &n)) {
    STRACE_ERROR(libc_memset, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t ptr = memset_intercept(memory, s, (char) c, n);
  STRACE_SUCCESS(libc_memset, "dest=%" PRIxADDR ", val=%x, len=%" PRIdADDR ", ret=%" PRIxADDR, ptr, (int)(char)c, n, ptr);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_memcpy(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t dest;
  addr_t src;
  size_t n;
  if (!intercept.TryGetArgs(memory, state, &dest, &src, &n)) {
    STRACE_ERROR(libc_memcpy, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t ptr = memcpy_intercept(memory, dest, src, n);
  STRACE_SUCCESS(libc_memcpy, "dest=%" PRIxADDR ", src=%" PRIxADDR ", len=%" PRIdADDR ", ret=%" PRIxADDR, dest, src, n, ptr);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_memmove(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t dest;
  addr_t src;
  size_t n;
  if (!intercept.TryGetArgs(memory, state, &dest, &src, &n)) {
    STRACE_ERROR(libc_memmove, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t ptr = memmove_intercept(memory, dest, src, n);
  STRACE_SUCCESS(libc_memmove, "dest=%" PRIxADDR ", src=%" PRIxADDR ", len=%" PRIdADDR ", ret=%" PRIxADDR, dest, src, n, ptr);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_strcpy(Memory *memory, State *state,
                              const ABI &intercept) {

  addr_t dest;
  addr_t src;

  if (!intercept.TryGetArgs(memory, state, &dest, &src)) {
    STRACE_ERROR(libc_strcpy, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t ptr = strcpy_intercept(memory, dest, src);
  STRACE_SUCCESS(libc_strcpy, "dest=%" PRIxADDR ", src=%" PRIxADDR ", ret=%" PRIxADDR, dest, src, ptr);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_strncpy(Memory *memory, State *state,
                              const ABI &intercept) {

  addr_t dest;
  addr_t src;
  size_t n;

  if (!intercept.TryGetArgs(memory, state, &dest, &src, &n)) {
    STRACE_ERROR(libc_strncpy, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  addr_t ptr = strncpy_intercept(memory, dest, src, n);
  STRACE_SUCCESS(libc_strncpy, "dest=%" PRIxADDR ", src=%" PRIxADDR ", len=%" PRIdADDR ", ret=%" PRIxADDR, dest, src, n, ptr);
  return intercept.SetReturn(memory, state, ptr);
}

template <typename ABI>
static Memory *Intercept_strlen(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t s;

  if (!intercept.TryGetArgs(memory, state,&s)) {
    STRACE_ERROR(libc_strlen, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  size_t size = strlen_intercept(memory, s);
  STRACE_SUCCESS(libc_strlen, "ptr=%" PRIxADDR ", len=%" PRIdADDR, s, size);
  return intercept.SetReturn(memory, state, size);
}


template <typename ABI>
static Memory *Intercept_strnlen(Memory *memory, State *state,
                              const ABI &intercept) {
  addr_t s;
  size_t n;

  if (!intercept.TryGetArgs(memory, state, &s, &n)) {
    STRACE_ERROR(libc_strnlen, "Couldn't get args");
    return intercept.SetReturn(memory, state, 0);
  }

  size_t size = strnlen_intercept(memory, s, n);
  STRACE_SUCCESS(libc_strnlen, "ptr=%" PRIxADDR ", max_len=%" PRIdADDR ", len=%" PRIdADDR, s, n, size);
  return intercept.SetReturn(memory, state, size);
}

template <typename ABI>
static Memory *Intercept_strncmp(Memory *memory, State *state,
                              const ABI &intercept) {
  return memory;
}

template <typename ABI>
static Memory *Intercept_strcmp(Memory *memory, State *state,
                              const ABI &intercept) {
  return memory;
}

}  // namespace
