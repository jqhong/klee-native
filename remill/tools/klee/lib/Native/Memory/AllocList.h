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

#include <memory>
#include <list>
#include <vector>

namespace klee {
namespace native {

union Address {
  uint64_t flat;
  struct {
    uint64_t offset :16;
    uint64_t must_be_0x1 :4;  // Helps to detect overflows/underflows.
    uint64_t size :16;  // Size of allocated object, used to find the `AllocList`.
    uint64_t alloc_index :24;  // Index of this object in the `AllocList`.
    uint64_t must_be_0xa :4;  // Helps to distinguish our address from mmap addresses.
  } __attribute__((packed));
};

class AddressSpace;
class PolicyHandler;

static uint8_t under_flow_check = 0x0a;
static uint8_t special_malloc_byte = 0xa;
static const unsigned kFreeValue = ~0U;

class AllocList {
 public:
  uint64_t Allocate(Address addr);
  bool TryFree(Address addr, AddressSpace *mem, PolicyHandler *policy_handler);
  bool TryRead(uint64_t addr, uint8_t *byte_out, AddressSpace *mem, PolicyHandler *policy_handler);
  bool TryWrite(uint64_t addr, uint8_t byte, AddressSpace *mem, PolicyHandler *policy_handler);
  void ExtendAllocations(uint64_t new_alloc_size);

  std::vector<unsigned> zeros;
  std::vector<std::shared_ptr<std::vector<uint8_t>>> allocations;
  unsigned num_free{0};
};

}  // namespace native
}  // namespace klee
