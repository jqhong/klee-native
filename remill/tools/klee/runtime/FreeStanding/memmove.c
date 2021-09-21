/*===-- memmove.c ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===*/

#include <stdlib.h>

void *memmove(void *dst, const void *src, size_t count) {
  auto a = (char *) dst;
  auto b = (const char *) src;

  if (src == dst)
    return dst;

  if (src > dst) {
    while (count--)
      *a++ = *b++;
  } else {
    a += count - 1;
    b += count - 1;
    while (count--)
      *a-- = *b--;
  }

  return dst;
}
