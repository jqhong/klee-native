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

#include "remill/Arch/Assembly.S"

#define STR_HELPER(id) #id
#define STR(id) STR_HELPER(id)
#define RTLD_NEXT 0xffffffffffffffff

.intel_syntax noprefix

TEXT_SECTION

.extern SYMBOL(dlsym)

DATA_SECTION
.Ldlsym_addr:
   .quad SYMBOL(dlsym)

#define C_INTERCEPT(name, id) \
   DATA_SECTION ; \
      .extern SYMBOL(real_ ## name) ; \
   .Lreal_ ## name ## _addr: \
      .quad SYMBOL(real_ ## name) ; \
      .extern SYMBOL(intercepted_ ## name) ; \
   .Lintercepted_ ## name ## _addr: \
      .quad SYMBOL(intercepted_ ## name) ; \
   TEXT_SECTION ; \
      .align 16 ; \
      ud2 ; ud2 ; ud2 ; ud2 ; \
      .globl SYMBOL(name) ; \
   SYMBOL(name): \
       jmp      qword ptr [rip + .Lintercepted_ ## name ##_addr ] ; \
       int      id ; \
       ret ; \
       push     r10 ; \
       mov      r10, qword ptr [rip + .Lreal_ ## name ## _addr ]; \
       mov      r10, qword ptr [r10]; \
       xchg     [rsp], r10 ; \
       ret ; \

#define ASM_INTERCEPT(name, id) \
   DATA_SECTION ; \
   .Laddr_ ## name : \
       .quad .Lfind_ ## name ; \
   .Lname_ ## name: \
       .asciz #name ; \
   TEXT_SECTION ; \
      .align 16 ; \
      ud2 ; ud2 ; ud2 ; ud2 ; \
      .globl SYMBOL(name) ; \
   SYMBOL(name): \
       jmp     qword ptr [rip + .Laddr_ ## name ] ; \
       int     id ; \
       ret ; \
   .Lfound_ ## name: \
       jmp     qword ptr [rip + .Laddr_ ## name ] ; \
   .Lfind_ ## name : \
       push    rax ; \
       push    rdi ; \
       push    rsi ; \
       push    rcx ; \
       push    rdx ; \
       push    rbx ; \
       push    rbp ; \
       push    r8 ; \
       push    r9  ; \
       push    r10  ; \
       push    r11  ; \
       push    r12 ; \
       push    r13 ; \
       push    r14 ; \
       push    r15 ; \
       xor     edi, edi; \
       not     rdi; \
       lea     rsi, [rip + .Lname_ ## name] ; \
       call    qword ptr [rip + .Ldlsym_addr] ; \
       mov     qword ptr [rip + .Laddr_ ## name], rax ; \
       pop     r15 ; \
       pop     r14 ; \
       pop     r13 ; \
       pop     r12 ; \
       pop     r11 ; \
       pop     r10 ; \
       pop     r9 ; \
       pop     r8 ; \
       pop     rbp ; \
       pop     rbx ; \
       pop     rdx ; \
       pop     rcx ; \
       pop     rsi ; \
       pop     rdi ; \
       pop     rax ; \
       jmp     .Lfound_ ## name ;

#define ALIAS(name, other_name) \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       jmp SYMBOL(other_name) ;

#define IGNORE(name) \
   TEXT_SECTION ; \
   .globl SYMBOL(name) ; \
   SYMBOL(name): \
       xor eax, eax ; \
       ret ;

#include "intercepts.inc"
