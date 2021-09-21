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

#include "Task.h"

Task *gCurrent = nullptr;

extern "C" {

bool symbolic_stdin();

LiftedFunc *__kleemill_get_lifted_function(Memory *, addr_t pc);

void __kleemill_log_state(State *state);

inline static void LogGPR64(char *&os, addr_t val, const char *reg_name){
  os = &os[sprintf(os, "  %s %016llx\n", reg_name, val)];
}

Memory * __remill_log_state(State *state, Memory *memory){
    //__kleemill_get_lifted_function(memory, state->gpr.rip.aword);
 /*
 char buff[512];
 auto os = &buff[0];
 LogGPR64(os, state->gpr.rip.aword, "RIP");
 LogGPR64(os, state->gpr.rsp.aword, "RSP");
 LogGPR64(os, state->gpr.rbp.aword, "RBP");
 LogGPR64(os, state->gpr.rax.aword, "RAX");
 LogGPR64(os, state->gpr.rbx.aword, "RBX");
 LogGPR64(os, state->gpr.rcx.aword, "RCX");
 LogGPR64(os, state->gpr.rdx.aword, "RDX");
 LogGPR64(os, state->gpr.rsi.aword, "RSI");
 LogGPR64(os, state->gpr.rdi.aword, "RDI");
 LogGPR64(os, state->gpr.r8.aword, "R8");
 LogGPR64(os, state->gpr.r9.aword, "R9");
 LogGPR64(os, state->gpr.r10.aword, "R10");
 LogGPR64(os, state->gpr.r11.aword, "R11");
 LogGPR64(os, state->gpr.r12.aword, "R12");
 LogGPR64(os, state->gpr.r13.aword, "R13");
 LogGPR64(os, state->gpr.r14.aword, "R14");
 LogGPR64(os, state->gpr.r15.aword, "R15");
 os[0] = '\n';
 os[1] = 0;
 puts(buff);
 */
 return memory;
}

Memory * __remill_function_call(State &state, addr_t pc, Memory *memory) {
  
  //puts("__remill_function_call");
  auto &task = reinterpret_cast<linux_task &>(state);
  if (CanContinue(task.location)) {
    task.time_stamp_counter += 1000;
    task.state = state;
    task.memory = memory;
    task.location = kTaskStoppedAtCallTarget;
    task.status = kTaskStatusRunnable;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_function_return(State &state, addr_t pc, Memory *memory) {

  //puts("__remill_function_return");
  auto &task = reinterpret_cast<linux_task &>(state);
  if (CanContinue(task.location)) {
    task.time_stamp_counter += 1000;
    task.memory = memory;
    task.state = state;
    task.location = kTaskStoppedAtReturnTarget;
    task.status = kTaskStatusRunnable;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_jump(State &state, addr_t pc, Memory *memory) {
  //puts("__remill_jump");
  auto &task = reinterpret_cast<linux_task &>(state);
  if (CanContinue(task.location)) {
    task.memory = memory;
    task.time_stamp_counter += 1000;
    task.location = kTaskStoppedAtJumpTarget;
    task.status = kTaskStatusRunnable;
    task.state = state;
    task.last_pc = pc;
    task.continuation = __kleemill_get_lifted_function(memory, pc);
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory *__kleemill_at_error(State &state, addr_t ret_addr, Memory *memory) {
  auto task = reinterpret_cast<Task &>(state);
  task.status = kTaskStatusError;
  task.location = kTaskStoppedAtError;
  puts("Error; unwinding\n");
  return memory;
}

Memory *__kleemill_at_unhandled_hypercall(State &state, addr_t ret_addr,
                                          Memory *memory) {

  auto task = reinterpret_cast<Task &>(state);
  task.status = kTaskStatusError;
  task.location = kTaskStoppedAtError;
  puts("Unhandled hypercall; unwinding\n");
  return memory;
}

Memory * __remill_missing_block(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    //puts("MISSING CAN CONTINUE");
    task.status = kTaskStatusResumable;
    task.location = kTaskStoppedAtMissingBlock;
    //task.continuation = __kleemill_get_lifted_function(memory, task.last_pc);//__kleemill_at_error;
    //task.last_pc = pc;
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

Memory * __remill_error(State &state, addr_t pc, Memory *memory) {

  auto &task = reinterpret_cast<Task &>(state);
  if (CanContinue(task.location)) {
    task.status = kTaskStatusError;
    task.location = kTaskStoppedAtError;
    task.continuation = __kleemill_at_error;
    task.last_pc = pc;
    //return task.continuation(state, task.last_pc, memory);
  }
  return memory;
}

uint8_t __remill_undefined_8(void) {
  return 0;
}

uint16_t __remill_undefined_16(void) {
  return 0;
}

uint32_t __remill_undefined_32(void) {
  return 0;
}

uint64_t __remill_undefined_64(void) {
  return 0;
}

float32_t __remill_undefined_f32(void) {
  return 0;
}

float64_t __remill_undefined_f64(void) {
  return 0;
}

Memory *__remill_barrier_load_load(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_load_store(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_store_load(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_barrier_store_store(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_atomic_begin(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_atomic_end(Memory *memory) {
  gCurrent->time_stamp_counter += 200;
  return memory;
}

Memory *__remill_compare_exchange_memory_8(Memory *memory, addr_t addr,
                                           uint8_t &expected, uint8_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_8(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_16(Memory *memory, addr_t addr,
                                            uint16_t &expected,
                                            uint16_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_16(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_32(Memory *memory, addr_t addr,
                                            uint32_t &expected,
                                            uint32_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_32(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_64(Memory *memory, addr_t addr,
                                            uint64_t &expected,
                                            uint64_t desired) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  if (current == expected) {
    memory = __remill_write_memory_64(memory, addr, desired);
  }
  expected = current;
  return memory;
}

Memory *__remill_compare_exchange_memory_128(Memory *memory, addr_t addr,
                                             uint128_t &expected,
                                             uint128_t &desired) {
  gCurrent->time_stamp_counter += 400;
  const auto lo = __remill_read_memory_64(memory, addr);
  const auto hi = __remill_read_memory_64(memory, addr + 8);
  const auto current = static_cast<uint128_t>(lo)
      | (static_cast<uint128_t>(hi) << 64);
  if (current == expected) {
    memory = __remill_write_memory_64(memory, addr,
                                      static_cast<uint64_t>(desired));
    memory = __remill_write_memory_64(memory, addr + 8,
                                      static_cast<uint64_t>(desired >> 64));
  }
  expected = current;
  return memory;
}

Memory *__remill_fetch_and_add_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current + value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current + value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current + value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_add_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current + value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current - value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current - value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current - value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_sub_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current - value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current & value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current & value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current & value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_and_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current & value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current | value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_16(Memory *memory, addr_t addr, uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current | value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_32(Memory *memory, addr_t addr, uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current | value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_or_64(Memory *memory, addr_t addr, uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current | value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_8(Memory *memory, addr_t addr, uint8_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_8(memory, addr);
  const uint8_t next = current ^ value;
  memory = __remill_write_memory_8(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_16(memory, addr);
  const uint16_t next = current ^ value;
  memory = __remill_write_memory_16(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_32(memory, addr);
  const uint32_t next = current ^ value;
  memory = __remill_write_memory_32(memory, addr, next);
  value = current;
  return memory;
}

Memory *__remill_fetch_and_xor_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  gCurrent->time_stamp_counter += 400;
  const auto current = __remill_read_memory_64(memory, addr);
  const uint64_t next = current ^ value;
  memory = __remill_write_memory_64(memory, addr, next);
  value = current;
  return memory;
}

extern "C" linux_task *__kleemill_create_task(State *state,
                                              Memory *memory);


int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }

  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));

  __kleemill_init(memory);

  State *state = reinterpret_cast<State *>(argv[1]);
  Task *task = __kleemill_create_task(state, memory);

  __kleemill_schedule();
  __kleemill_fini();
  return EXIT_SUCCESS;
}

// ----------------USE ME FOR DEMO ----------------------
/*
int main(int argc, char *argv[3], char *envp[]) {
  puts("in main");
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);

  uint32_t sym_u32;
  klee_make_symbolic(&sym_u32, sizeof sym_u32, "sym_u32");

  uint64_t sym_u64 = 0;
  klee_make_symbolic(&sym_u64, sizeof sym_u64, "sym_u64");
  klee_assume(sym_u64 <= 2);

  __remill_write_memory_32(memory, state->gpr.rsp.aword, sym_u32);
  //__remill_write_memory_8(memory, state->gpr.rsp.aword + 1 + a, sym_byte2);
  uint8_t res = __remill_read_memory_8(memory, state->gpr.rsp.aword + sym_u64);

  if (res > 0x25) {
    puts("You lose: ");
  } else {
    puts("You Win: ");
  }
  printf("0x%x\n", static_cast<uint32_t>(klee_get_value_i32(res)));
  __kleemill_fini();
  puts("done");
  return EXIT_SUCCESS;
}
*/

// ----------------USE ME FOR DEMO ----------------------

/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }

  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));

  __kleemill_init(memory);

  State *state = reinterpret_cast<State *>(argv[1]);
  //Task *task = __kleemill_create_task(state, memory);
  auto chunk = malloc(0x15);
  auto chunk2 = malloc(0x15);

  free(chunk);

  auto chunk3 = malloc(0x15);

  free(chunk2);
  
  auto chunk4 = malloc(0x18);
  
  free(chunk3);
  free(chunk4);
  free(chunk2);
  void *chunk5 = malloc(0x16);
  __remill_write_memory_32(memory, reinterpret_cast<addr_t>(chunk5), 
          0x89124441);
   uint32_t bytes =
       __remill_read_memory_32(memory, reinterpret_cast<addr_t>(chunk5));
   printf("read bytes were %lx\n", bytes);
   //free(chunk5);
    __remill_write_memory_32(memory, reinterpret_cast<addr_t>(chunk5),
          0x69696969);
  uint8_t a;
  void *chunk5 = malloc(0x16);
  __remill_write_memory_32(memory, reinterpret_cast<addr_t>(chunk5), 
          0x89124441);
   uint32_t bytes =
       __remill_read_memory_32(memory, reinterpret_cast<addr_t>(chunk5));
  printf("read bytes before fork were %lx\n", bytes);
  
  klee_make_symbolic(&a, sizeof(a), "a");

  if (a > 50) {
    uint32_t bytes2 =
       __remill_read_memory_32(memory, reinterpret_cast<addr_t>(chunk5));
 
    printf("read bytes fork1 case were %lx\n", bytes2);
    __remill_write_memory_32(memory, reinterpret_cast<addr_t>(chunk5), 
          0x61616161);
    uint32_t bytes4 =
       __remill_read_memory_32(memory, reinterpret_cast<addr_t>(chunk5));
    printf("read bytes fork1 case were %lx\n", bytes4);
    free(chunk5);
  } else {
    uint32_t bytes3 =
       __remill_read_memory_32(memory, reinterpret_cast<addr_t>(chunk5));
    printf("read bytes fork2 case were %lx\n", bytes3);
    __remill_write_memory_32(memory, reinterpret_cast<addr_t>(chunk5), 
          0x42424242);
    uint32_t bytes5 = __remill_read_memory_32(memory, 
            reinterpret_cast<addr_t>(chunk5));
    printf("read bytes fork2 case were %lx\n", bytes5);
    free(chunk5);
    __remill_read_memory_32(memory, 
            reinterpret_cast<addr_t>(chunk5));

  }
 
  __kleemill_schedule();
  __kleemill_fini();
  return EXIT_SUCCESS;
}

*/

/*
int main(int argc, char *argv[3], char *envp[]) {
  puts("in main");
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  
  uint32_t sym_u32;
  klee_make_symbolic(&sym_u32, sizeof sym_u32, "sym_u32");

  uint64_t sym_u64 = 0;
  klee_make_symbolic(&sym_u64, sizeof sym_u64, "sym_u64");
  klee_assume(sym_u64 <= 2);

  __remill_write_memory_32(memory, state->gpr.rsp.aword, sym_u32);
  //__remill_write_memory_8(memory, state->gpr.rsp.aword + 1 + a, sym_byte2);
  uint8_t res = __remill_read_memory_8(memory, state->gpr.rsp.aword + sym_u64);

  if (res > 0x25) {
    puts("You lose: ");
  } else {
    puts("You Win: ");
  }
  printf("0x%x\n", static_cast<uint32_t>(klee_get_value_i32(res)));
  __kleemill_fini();
  puts("done");
  return EXIT_SUCCESS;
}
*/

/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  uint8_t sym_byte1; // = 0xaabbccdd;
  uint8_t sym_byte2 = 0x69; // = 0xaabbccdd;
  
  klee_make_symbolic(&sym_byte1, sizeof sym_byte1, "sb1");
  klee_assume(sym_byte1 > 0x80);
  uint64_t a;
  klee_make_symbolic(&a, sizeof a, "a");
  klee_assume(a <= 1);
 
  __remill_write_memory_8(memory, state->gpr.rsp.aword + a, sym_byte1);
  __remill_write_memory_8(memory, state->gpr.rsp.aword + 1 + a, sym_byte2);
  uint16_t res = __remill_read_memory_16(memory, state->gpr.rsp.aword + a);
  if (res > 0x25) {
    puts("YOu lose : /");
  } else {
    printf("You Win!!\n");
  }
  printf("0x%lx\n", static_cast<uint16_t>(klee_get_value_i32(res)));
  __kleemill_fini();
  return EXIT_SUCCESS;
}
*/
/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  uint8_t sym_byte1; // = 0xaabbccdd;
  uint8_t sym_byte2 = 0x69; // = 0xaabbccdd;
  
  klee_make_symbolic(&sym_byte1, sizeof sym_byte1, "sb1");
  klee_assume(sym_byte1 > 0x80);
  
  __remill_write_memory_8(memory, state->gpr.rsp.aword, sym_byte1);
  __remill_write_memory_8(memory, state->gpr.rsp.aword + 1, sym_byte2);
  uint16_t res = __remill_read_memory_16(memory, state->gpr.rsp.aword);
  if (res > 0x25) {
    puts("YOu lose : /");
  } else {
    printf("You Win!!\n");
  }
  printf("0x%lx\n", static_cast<uint16_t>(klee_get_value_i32(res)));
  __kleemill_fini();
  return EXIT_SUCCESS;
}
*/
/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);

  uint64_t sym_byte1;
  klee_make_symbolic(&sym_byte1, sizeof(sym_byte1), "sym_byte1");
  klee_assume(sym_byte1 > 0x1337);

  uint64_t a = 0;
  klee_make_symbolic(&a, sizeof(a), "a");
  klee_assume(a <= 2);

  uint64_t byte2 = 0x1111111111111111;
  __remill_write_memory_64(memory, state->gpr.rsp.aword + a, sym_byte1);
  __remill_write_memory_64(memory, state->gpr.rsp.aword + a + 8, byte2);
  
  uint64_t res = __remill_read_memory_64(memory, state->gpr.rsp.aword);
  printf("0x%lx\n", klee_get_value_i64(res));
  __kleemill_fini();
  return EXIT_SUCCESS;
}
*/
/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  
  uint32_t sym_byte1 = 0x69ff69ff;
  uint32_t sym_byte2 = 0x11111111;
  klee_make_symbolic(&sym_byte2, sizeof(sym_byte2),"sym_byte2");
  klee_assume(sym_byte2 > 0x1337);

  uint64_t a = 0;
  klee_make_symbolic(&a, sizeof(a), "a");
  klee_assume(a <= 8);
  

  __remill_write_memory_32(memory, state->gpr.rsp.aword, sym_byte1);
  __remill_write_memory_32(memory, state->gpr.rsp.aword + 4, sym_byte2);
  //__remill_write_memory_64(memory, state->gpr.rsp.aword + 8, a);

  uint64_t res = __remill_read_memory_64(memory, state->gpr.rsp.aword + a);
  if (res < 0x1337) {
    puts("YOu lose : /");
  } else {
    printf("You Win!!\n");
  }

  printf("%lx\n", klee_get_value_i64(res));
  __kleemill_fini();
  return EXIT_SUCCESS;

}
*/

/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  uint16_t sym_byte1 = 0x69ff;
  uint16_t sym_byte2 = 0x70ff;

  //klee_make_symbolic(&sym_byte2, sizeof(sym_byte2),"sym_byte2");
  
  __remill_write_memory_16(memory, state->gpr.rsp.aword, sym_byte1);
  __remill_write_memory_16(memory, state->gpr.rsp.aword + 2, sym_byte2);
  uint64_t a;
  klee_make_symbolic(&a, sizeof(a), "a");
  klee_assume(a <= 2);
  
  uint16_t res = __remill_read_memory_16(memory, state->gpr.rsp.aword + a);
  printf("%x\n", static_cast<uint16_t>(klee_get_value_i32(res)));
  __kleemill_fini();
  return EXIT_SUCCESS;
}
*/

/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }

  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));
  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  uint64_t a;
  uint8_t sym_byte1 = 0x41;
  uint8_t sym_byte2 = 0x42;
  uint8_t sym_byte3 = 0x43;
  uint8_t sym_byte4 = 0x44;

  klee_make_symbolic(&a, sizeof(a), "a");
  klee_assume(a <= 3);

  __remill_write_memory_8(memory, state->gpr.rsp.aword + a, sym_byte1);
  __remill_write_memory_8(memory, state->gpr.rsp.aword + 2, sym_byte3);
  __remill_write_memory_8(memory, state->gpr.rsp.aword + 3, sym_byte4);
  
  uint8_t res = __remill_read_memory_8(memory, state->gpr.rsp.aword + a);
  printf("res: %d a: %d\n", res, klee_get_value_i32(a));
  
  if (res == 0x41) {
    puts("A case");
  } else if (res == 0x42){
    puts("B case");
  } else if (res == 0x43){
    puts("C case");
  } else if (res == 0x44){
    puts("D case");
  }

 __kleemill_fini();
  return EXIT_SUCCESS;
}
*/
// __remill_write_memory_64(memory, state->gpr.rsp.aword,a);
 /*
  puts("Back in runtime after mem write");
  int16_t sym_bytes = __remill_read_memory_16(
			memory, state->gpr.rsp.aword + 6);
  puts("After mem read");
  if(sym_bytes > 0) {
      auto b = klee_get_value_i32(sym_bytes);
      printf("a when sym_bytes > 0: %d\n", b);
      return 1;
  } else if (sym_bytes == 0) {
      printf("a at sym_bytes == 0: %d\n", sym_bytes);
      return 0;
  } else {
      auto b = klee_get_value_i32(sym_bytes);
      printf("a at sym_bytes < 0: %d\n", b);
      return -1;
  }

  */
 
/*
int main(int argc, char *argv[3], char *envp[]) {
  if (argc != 3) {
    return EXIT_FAILURE;
  } else if (strcmp("klee-exec", argv[0])) {
    return EXIT_FAILURE;
  }
  Memory *memory = nullptr;
  memcpy(&memory, argv[2], sizeof(memory));


  __kleemill_init(memory);
  State *state = reinterpret_cast<State *>(argv[1]);
  int64_t a;
  klee_make_symbolic(&a, sizeof(a), "a");
  __remill_write_memory_64(memory, state->gpr.rsp.aword, a);
  int8_t sym_bytes = __remill_read_memory_8(memory, state->gpr.rsp.aword+4);
 
  if(sym_bytes > 0) {
      auto b = klee_get_value_i32(sym_bytes);
      printf("a at this value is: %d\n", b);
      return 1;
  } else if (sym_bytes == 0) {
      printf("a at this value is: %d\n", sym_bytes);
      return 0;
  } else {
      auto b = klee_get_value_i32(sym_bytes);
      printf("a at this value is: %d\n", b);
      return -1;
  }
  __kleemill_fini();
  return EXIT_SUCCESS;
}
*/

}
