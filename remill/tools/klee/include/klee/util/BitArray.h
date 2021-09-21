//===-- BitArray.h ----------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#pragma once

namespace klee {

// XXX would be nice not to have
// two allocations here for allocated
// BitArrays
class BitArray {
 private:
  uint32_t * const bits;

 protected:
  static size_t length(size_t size) {
    return (size + 31) / 32;
  }

 public:
  inline BitArray(size_t size, bool value = false)
      : bits(new uint32_t[length(size)]) {
    memset(bits, value ? 0xFF : 0, sizeof(*bits) * length(size));
  }

  inline BitArray(const BitArray &b, size_t size)
      : bits(new uint32_t[length(size)]) {
    memcpy(bits, b.bits, sizeof(*bits) * length(size));
  }

  inline ~BitArray(void) {
    delete[] bits;
  }

  inline bool get(size_t idx) {
    return (bool) ((bits[idx / 32] >> (idx & 0x1F)) & 1);
  }

  inline void set(size_t idx) {
    bits[idx / 32] |= 1 << (idx & 0x1F);
  }

  inline void unset(size_t idx) {
    bits[idx / 32] &= ~(1 << (idx & 0x1F));
  }

  inline void set(size_t idx, bool value) {
    if (value) {
      set(idx);
    } else {
      unset(idx);
    }
  }
};

}  // namespace klee
