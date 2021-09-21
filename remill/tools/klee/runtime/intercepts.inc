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

#ifndef ASM_INTERCEPT
# define ASM_INTERCEPT(name, num)
#endif

#ifndef C_INTERCEPT
# define C_INTERCEPT(name, num)
#endif

#ifndef ALIAS
# define ALIAS(name, other_name)
#endif

#ifndef IGNORE
# define IGNORE(name)
#endif

//ASM_INTERCEPT(strtol, 0xa1 )

C_INTERCEPT(malloc, 0x81)
C_INTERCEPT(calloc, 0x82)
C_INTERCEPT(realloc, 0x83)
C_INTERCEPT(free, 0x84)

ASM_INTERCEPT(memalign, 0x85)
ASM_INTERCEPT(malloc_usable_size, 0x86)

C_INTERCEPT(memset, 0x87)
C_INTERCEPT(memcpy, 0x88)
C_INTERCEPT(memmove, 0x89)
C_INTERCEPT(strcpy, 0x8a)
C_INTERCEPT(strncpy, 0x8b)
C_INTERCEPT(strlen, 0x8c)
// C_INTERCEPT(strnlen, 0x8d)

//  C_INTERCEPT(strncmp, 0x91) implemented as just LD_PRELOAD
//  C_INTERCEPT(strcmp, 0x92) implemented as just LD_PRELOAD


//ALIAS(__strncmp_sse42, strncmp)
ALIAS(__libc_malloc, malloc)
ALIAS(__GI___libc_malloc, malloc)
ALIAS(dlmalloc, malloc)
ALIAS(pvalloc, malloc)
ALIAS(valloc, malloc)
ALIAS(_Znaj, malloc)
ALIAS(_Znwj, malloc)
ALIAS(_Znam, malloc)
ALIAS(_Znwm, malloc)

ALIAS(aligned_alloc, memalign)

ALIAS(__libc_calloc, calloc)
ALIAS(__GI___libc_calloc, calloc)
ALIAS(dlcalloc, calloc)

ALIAS(__libc_free, free)
ALIAS(__GI___libc_free, free)
ALIAS(dlfree, free)
ALIAS(_ZdaPv, free)
ALIAS(_ZdlPv, free);

IGNORE(mallinfo)
IGNORE(__libc_mallinfo)
IGNORE(__GI___libc_mallinfo)

IGNORE(mallopt)
IGNORE(__libc_mallopt)
IGNORE(__GI___libc_mallopt)

IGNORE(malloc_stats)
IGNORE(__libc_malloc_stats)
IGNORE(__GI___libc_malloc_stats)

IGNORE(malloc_trim)
IGNORE(__libc_malloc_trim)
IGNORE(__GI___libc_malloc_trim)

#undef ASM_INTERCEPT
#undef C_INTERCEPT
#undef ALIAS
#undef IGNORE
