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

#include <glog/logging.h>
#include "Native/Memory/AllocList.h"
#include "Native/Memory/PolicyHandler.h"

namespace klee {
namespace native {

static const unsigned kMinNumFree = 32;

uint64_t AllocList::Allocate(Address addr) {

  // Try to re-use a random one.
  size_t free_slot = 0;
  bool found_free = false;

  if (num_free >= kMinNumFree) {
    if (auto max_j = zeros.size()) {
      uint64_t i = static_cast<size_t>(rand()) % max_j;
      for (size_t j = 0; j < max_j; ++j) {
        free_slot = (i + j) % max_j;
        if (zeros[free_slot]) {
          found_free = kFreeValue;
          break;
        }
      }
    }
  }

  auto mem = std::make_shared<std::vector<uint8_t>>();
  mem->resize(addr.size);

  if (!found_free) {
    addr.alloc_index = allocations.size();
    allocations.emplace_back(std::move(mem));
    zeros.push_back(0);

  } else {
    num_free--;
    addr.alloc_index = free_slot;
    allocations[free_slot] = std::move(mem);
    zeros[free_slot] = 0;
  }

  return addr.flat;
}

bool AllocList::TryFree(Address address, AddressSpace *mem,  PolicyHandler *policy_handler) {
  auto alloc_index = address.alloc_index;
  bool res;

  if (address.offset != 0) {
     res = false;
     if (policy_handler->HandleFreeOffset(mem, address, &res)){
       return res;
     }
     address.offset = 0;
     // adjusts the offset?
   }

  if (address.alloc_index >= zeros.size()) {
    res = false;
    if (policy_handler -> HandleFreeUnallocatedMem(mem, address, &res, this)) {
      return res;
    }
  }

  auto base = zeros[alloc_index];

  if (base == kFreeValue) {
    res = false;
    if (policy_handler -> HandleDoubleFree(mem, address, &res, this)) {
      return res;
    }
  }

  auto &alloc = allocations[alloc_index];

  if (!alloc) {
    res =false;
    if(policy_handler->HandlePseudoUseAfterFree(mem, address, &res, this)) {
      return res;
    }
  }

  alloc.reset();  // Free the std::vector.
  num_free++;
  zeros[alloc_index] = kFreeValue;
  return true;
}

void AllocList::ExtendAllocations(uint64_t new_alloc_size) {

}

bool AllocList::TryRead(uint64_t addr, uint8_t *byte_out, AddressSpace *mem, PolicyHandler *policy_handler) {
  Address address = {};
  address.flat = addr;
  bool res;
  auto base = zeros.at(address.alloc_index);
  if (address.alloc_index >= allocations.size()) {
     res = false;
     if (policy_handler->HandleInvalidOutOfBoundsHeapRead(mem, address, &res, this)) {
       return res;
     }
     ExtendAllocations(address.alloc_index + 1);
   }

   if (base == kFreeValue) {
     res = false;
     if (policy_handler->HandleReadUseAfterFree(mem, address, &res, this)) {
       return res;
     }
     // TODO(sai) perhaps do a UAF correction??
   }

   if (address.must_be_0x1 != 0x1) {
     res = false;
     if (policy_handler->HandleHeapReadUnderflow(mem, address, &res, this)) {
       return res;
     }
   // TODO(sai) perhaps correct underflow??
   }

   if (address.offset >= address.size){
     res = false;
     if (policy_handler->HandleHeapReadOverflow(mem, address, byte_out,&res, this)) {
       return res;
     }
   }

  *byte_out = allocations[address.alloc_index]->at(base + address.offset);
  return true;
}

bool AllocList::TryWrite(uint64_t addr, uint8_t byte, AddressSpace *mem, PolicyHandler *policy_handler) {
  Address address = {};
  address.flat = addr;
  bool res;
  auto base = zeros.at(address.alloc_index);

  if (address.alloc_index >= allocations.size()) {
    res = false;
    if (policy_handler->HandleInvalidOutOfBoundsHeapWrite(mem, address, &res, this)) {
      return res;
    }
    ExtendAllocations(address.alloc_index + 1);
  }

  if (base == kFreeValue) {
    res = false;
    if (policy_handler->HandleWriteUseAfterFree(mem, address, &res, this)) {
      return res;
    }
    // TODO(sai) perhaps do a UAF correction
  }

  if (address.must_be_0x1 != 0x1) {
    res = false;
    if (policy_handler->HandleHeapWriteUnderflow(mem, address, &res, this)) {
      return res;
    }
  // TODO(sai) perhaps correct underflow
  }

  if (address.offset >= address.size){
    res = false;
    if (policy_handler->HandleHeapWriteOverflow(mem, address, &res, this)) {
      return res;
    }
    //TODO(sai) Extend individual allocation
  }

  auto &alloc_buffer = allocations[address.alloc_index];

  if(!alloc_buffer) {
    if (policy_handler->HandlePseudoUseAfterFree(mem, address, &res, this)) {
      return false;
    }
  }

  if (alloc_buffer.use_count() > 1) {
    auto old_array = alloc_buffer.get();
    auto new_array = std::make_shared<std::vector<uint8_t>>();
    new_array->resize(address.size);
    memcpy(new_array->data(), old_array->data(), address.size);
    alloc_buffer = std::move(new_array);
  }

  allocations[address.alloc_index]->at(base + address.offset) = byte;
  return true;
}

}  // namespace native
}  // namespace klee
