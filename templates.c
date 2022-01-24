/// Intel x86 Executor.
/// File: Measurement templates for various threat models
///
// -----------------------------------------------------------------------------------------------
// Based originally on the Andreas Abel's nanoBench
// Copyright (C) 2020 Oleksii Oleksenko
//
// Copyright notices from the original nanoBench code:
// -----------------------------------------------------------------------------------------------
//
// This program is free software: you can redistribute it and/or modify it under the terms
// of version 3 of the GNU Affero General Public License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License along with
// this program.
// If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------------------------
//
// This file is subject to the terms and conditions of the GNU General Public License.
// See the file LICENCE in the main directory of the Revizor distribution for more details.
//

// -----------------------------------------------------------------------------------------------
// Note on registers.
// Some of the registers are reserved for a specific purpose and should never be overwritten.
// These include:
//   R8 - performance counter #1
//   R9 - performance counter #2
//   R10 - performance counter #3
//   R11 - hardware trace
//   R12 - SMI counter
//   R13 - input seed
//   R14 - sandbox base address
//

#include "x86-executor.h"

#define MAGIC_BYTES_INIT 0x10b513b1C2813F04
#define MAGIC_BYTES_CODE 0x20b513b1C2813F04
#define MAGIC_BYTES_RSP_ADDRESS 0x30b513b1C2813F04
#define MAGIC_BYTES_SANDBOX_BASE 0x40b513b1C2813F04
#define UNUSED1 0x50b513b1C2813F04
#define UNUSED2 0x60b513b1C2813F04
#define UNUSED3 0x70b513b1C2813F04
#define MAGIC_BYTES_STACK_BASE 0x80b513b1C2813F04
#define MAGIC_BYTES_HTRACE 0x90b513b1C2813F04
#define MAGIC_BYTES_PFC_READING 0xA0b513b1C2813F04
#define MAGIC_BYTES_TEMPLATE_END 0xB0b513b1C2813F04

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

// =================================================================================================
// Template Loader
// =================================================================================================
int starts_with_magic_bytes(char *c, int64_t magic_bytes) {
    return (*((int64_t *) c) == magic_bytes);
}

size_t get_distance_to_code(char *measurement_template, size_t templateI) {
    size_t dist = 0;
    while (!starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_CODE)) {
        templateI++;
        dist++;
    }
    return dist;
}

void load_template(char *measurement_template) {
    size_t templateI = 0;
    size_t rcI = 0;

    while (!starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_TEMPLATE_END)) {
        if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_INIT)) {
            templateI += 8;
            size_t dist = get_distance_to_code(measurement_template, templateI);
            size_t nFill = (64 - ((uintptr_t) & runtime_code[rcI + dist] % 64)) % 64;
            nFill += alignment_offset;
            for (size_t i = 0; i < nFill; i++) {
                runtime_code[rcI++] = '\x90';
            }
        } else if (starts_with_magic_bytes(&measurement_template[templateI], MAGIC_BYTES_CODE)) {
            templateI += 8;

            // copy the sample
            memcpy(&runtime_code[rcI], code, code_length);
            rcI += code_length;

            if (debug) {
                runtime_code[rcI++] = '\xCC'; // INT3
            }
        } else if (starts_with_magic_bytes(&measurement_template[templateI],
                                           MAGIC_BYTES_HTRACE)) {
            *(void **) (&runtime_code[rcI]) = latest_htrace;
            templateI += 8;
            rcI += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI],
                                           MAGIC_BYTES_PFC_READING)) {
            *(void **) (&runtime_code[rcI]) = (void *) latest_pfc_readings;
            templateI += 8;
            rcI += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI],
                                           MAGIC_BYTES_RSP_ADDRESS)) {
            *(void **) (&runtime_code[rcI]) = &RSP_mem;
            templateI += 8;
            rcI += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI],
                                           MAGIC_BYTES_SANDBOX_BASE)) {
            *(void **) (&runtime_code[rcI]) = sandbox_base;
            templateI += 8;
            rcI += 8;
        } else if (starts_with_magic_bytes(&measurement_template[templateI],
                                           MAGIC_BYTES_STACK_BASE)) {
            *(void **) (&runtime_code[rcI]) = stack_base;
            templateI += 8;
            rcI += 8;
        } else {
            runtime_code[rcI++] = measurement_template[templateI++];
        }
    }
    templateI += 8;
    do {
        runtime_code[rcI++] = measurement_template[templateI++];
    } while (measurement_template[templateI - 1] != '\xC3'); // 0xC3 = ret
}


// =================================================================================================
// Template building blocks
// =================================================================================================
#define asm_volatile_intel(ASM) \
    asm volatile( \
    ".intel_syntax noprefix                  \n" \
    ASM \
    ".att_syntax noprefix                    ") \

#define READ_MSR_START(ID, DEST)                          \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "sub "DEST", rdx                         \n"

#define READ_MSR_END(ID, DEST)                            \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "add "DEST", rdx                         \n"

#define READ_SMI_START(DEST) READ_MSR_START("0x00000034", DEST)
#define READ_SMI_END(DEST) READ_MSR_END("0x00000034", DEST)

#define READ_PFC_ONE(ID) \
        "mov rcx, "ID" \n"      \
        "lfence; rdpmc; lfence \n" \
        "shl rdx, 32; or rdx, rax \n"

#define READ_PFC_START() \
        READ_PFC_ONE("1") \
        "sub r10, rdx \n" \
        READ_PFC_ONE("2") \
        "sub r9, rdx \n" \
        READ_PFC_ONE("3") \
        "sub r8, rdx \n"

#define READ_PFC_END() \
        READ_PFC_ONE("1") \
        "add r10, rdx \n" \
        READ_PFC_ONE("2") \
        "add r9, rdx \n" \
        READ_PFC_ONE("3") \
        "add r8, rdx \n"

#define SB_FLUSH(TMP, REPS)                          \
        "mov "TMP", "REPS"                          \n" \
        "1: sfence                                  \n" \
        "dec "TMP"; jnz 1b                          \n"

#define SET_REGISTERS() \
        "movq rsp, "STRINGIFY(MAGIC_BYTES_SANDBOX_BASE)" \n" \
        "subq rsp, "STRINGIFY(REG_INITIALIZATION_REGION_SIZE)" \n" \
        "popq rax \n" \
        "popq rbx \n" \
        "popq rcx \n" \
        "popq rdx \n" \
        "popq rsi \n" \
        "popq rdi \n" \
        "popfq \n" \
        "popq rsp \n" \
        "mov rbp, rsp \n"

inline void prologue(void) {
    // As we don't use a compiler to track clobbering,
    // we have to save the callee-saved regs
    asm_volatile_intel("" \
        "push rbx\n" \
        "push rbp\n" \
        "push r12\n" \
        "push r13\n" \
        "push r14\n" \
        "push r15\n" \
        "pushfq\n" \
        "mov r15, "STRINGIFY(MAGIC_BYTES_RSP_ADDRESS)"\n" \
        "mov [r15], rsp\n");

    // Write the sandbox base address into R14;
    // used to calculate the addresses of all other mem. regions
    asm_volatile_intel("" \
        "mov rax, 0\n" \
        "mov rbx, 0\n" \
        "mov rcx, 0\n" \
        "mov rdx, 0\n" \
        "mov rsi, 0\n" \
        "mov rdi, 0\n" \
        "mov r8,  0\n" \
        "mov r9,  0\n" \
        "mov r10, 0\n" \
        "mov r11, 0\n" \
        "mov r12, 0\n" \
        "mov r13, 0\n" \
        "mov r15, 0\n" \
        "mov r14, "STRINGIFY(MAGIC_BYTES_SANDBOX_BASE)"\n");

    // start monitoring SMIs
    asm_volatile_intel(READ_SMI_START("r12"));
}

inline void epilogue(void) {
    // if we see no SMI interrupts, store the cache map (r11)
    // otherwise, store zero
    asm_volatile_intel(""\
        READ_SMI_END("r12") \
       "mov rax, "STRINGIFY(MAGIC_BYTES_HTRACE)" \n" \
       "mov rbx, "STRINGIFY(MAGIC_BYTES_PFC_READING)" \n" \
        "cmp r12, 0; jne 1f \n" \
        "   mov [rax], r11 \n" \
        "   mov [rbx], r10 \n" \
        "   mov [rbx + 8], r9 \n" \
        "   mov [rbx + 16], r8 \n" \
        "   jmp 2f \n" \
        "1: \n" \
        "   mov qword ptr [rax], 0 \n" \
        "2: \n");

    // done
    asm volatile(                                         \
        ".intel_syntax noprefix\n"                        \
        "mov r15, "STRINGIFY(MAGIC_BYTES_RSP_ADDRESS)"\n" \
        "mov rsp, [r15]\n"                                \
        "popfq\n"                                         \
        "pop r15\n"                                       \
        "pop r14\n"                                       \
        "pop r13\n"                                       \
        "pop r12\n"                                       \
        "pop rbp\n"                                       \
        "pop rbx\n"                                       \
        ".att_syntax noprefix");
    asm(".quad "STRINGIFY(MAGIC_BYTES_TEMPLATE_END));
}


// =================================================================================================
// L1D Prime+Probe
// =================================================================================================
// TODO: generate this code dynamically
#if L1D_ASSOCIATIVITY == 8
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
        "       mov "TMP", "OFFSET"                         \n" \
        "       add "TMP", ["BASE" + "TMP"]                 \n" \
        "       add "TMP", ["BASE" + "TMP" + 4096]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 8192]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 12288]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 16384]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 20480]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 24576]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 28672]         \n" \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

#define PROBE(BASE, OFFSET, TMP, DEST)                  \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; lfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, "OFFSET"                       \n" \
        "   add rax, ["BASE" + rax]                 \n" \
        "   add rax, ["BASE" + rax + 4096]          \n" \
        "   add rax, ["BASE" + rax + 8192]          \n" \
        "   add rax, ["BASE" + rax + 12288]         \n" \
        "   add rax, ["BASE" + rax + 16384]         \n" \
        "   add rax, ["BASE" + rax + 20480]         \n" \
        "   add rax, ["BASE" + rax + 24576]         \n" \
        "   add rax, ["BASE" + rax + 28672]         \n" \
        "   mov rcx, 0                              \n" \
        "   lfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 8; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"
#elif L1D_ASSOCIATIVITY == 12
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
        "       mov "TMP", "OFFSET"                         \n" \
        "       add "TMP", ["BASE" + "TMP"]                 \n" \
        "       add "TMP", ["BASE" + "TMP" + 4096]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 8192]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 12288]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 16384]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 20480]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 24576]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 28672]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 32768]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 36864]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 40960]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 45056]         \n" \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

#define PROBE(BASE, OFFSET, TMP, DEST)                  \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; lfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, "OFFSET"                       \n" \
        "   add rax, ["BASE" + rax]                 \n" \
        "   add rax, ["BASE" + rax + 4096]          \n" \
        "   add rax, ["BASE" + rax + 8192]          \n" \
        "   add rax, ["BASE" + rax + 12288]         \n" \
        "   add rax, ["BASE" + rax + 16384]         \n" \
        "   add rax, ["BASE" + rax + 20480]         \n" \
        "   add rax, ["BASE" + rax + 24576]         \n" \
        "   add rax, ["BASE" + rax + 28672]         \n" \
        "   add rax, ["BASE" + rax + 32768]         \n" \
        "   add rax, ["BASE" + rax + 36864]         \n" \
        "   add rax, ["BASE" + rax + 40960]         \n" \
        "   add rax, ["BASE" + rax + 45056]         \n" \
        "   mov rcx, 0                              \n" \
        "   lfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 12; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"
#endif

void template_l1d_prime_probe(void) {
    prologue();

    // Prime
    asm_volatile_intel(""\
        "mov rax, r14                              \n" \
        "sub rax, "STRINGIFY(EVICT_REGION_OFFSET)" \n" \
        PRIME("rax", "rbx", "rcx", "rdx", "16"));

    // Push empty values into the store buffer (just in case)
    asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    asm_volatile_intel(READ_PFC_START());

    // Initialize registers
    asm_volatile_intel(SET_REGISTERS());

    // indicate the beginning of the test case
    // used to align the test case code in memory
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));

    // Execute the test case
    asm("lfence\n"
        ".quad "STRINGIFY(MAGIC_BYTES_CODE)
        "\nmfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Probe and store the resulting eviction bitmap map into r11
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(""\
        "mov r15, r14                              \n" \
        "sub r15, "STRINGIFY(EVICT_REGION_OFFSET)" \n" \
        PROBE("r15", "rbx", "r13", "r11"));

    epilogue();
}

// =================================================================================================
// L1D Flush+Reload
// =================================================================================================
#define FLUSH(BASE, OFFSET) \
        "mfence                                     \n" \
        "mov "OFFSET", 0                            \n" \
        "1: lfence                                  \n" \
        "   clflush qword ptr ["BASE" + "OFFSET"]   \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n" \
        "mfence                                     \n"

#define RELOAD(BASE, OFFSET, TMP, DEST)                 \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; lfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
        "   mov rcx, 0                              \n" \
        "   lfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

void template_l1d_flush_reload(void) {
    prologue();

    // Flush
    asm_volatile_intel(
        "mov rbx, r14\n" \
        "add rbx, 0\n" \
        FLUSH("rbx", "rax"));

    // Push empty values into the store buffer (just in case)
    asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    asm_volatile_intel(READ_PFC_START());

    // Initialize registers
    asm_volatile_intel(SET_REGISTERS());

    // indicate the beginning of the test case
    // used to align the test case code in memory
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));

    // Execute the test case
    asm("lfence\n"
        ".quad "STRINGIFY(MAGIC_BYTES_CODE)
        "\nmfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Reload
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(
        "mov r15, r14\n" \
        "add r15, 0\n" \
        RELOAD("r15", "rbx", "r13", "r11"));

    epilogue();
}

void template_l1d_evict_reload(void) {
    prologue();

    // Prime
    asm_volatile_intel(""\
        "mov rax, r14                              \n" \
        "sub rax, "STRINGIFY(EVICT_REGION_OFFSET)" \n" \
        PRIME("rax", "rbx", "rcx", "rdx", "16"));

    // Push empty values into the store buffer (just in case)
    asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    asm_volatile_intel(READ_PFC_START());

    // Initialize registers
    asm_volatile_intel(SET_REGISTERS());

    // indicate the beginning of the test case
    // used to align the test case code in memory
    asm(".quad "STRINGIFY(MAGIC_BYTES_INIT));

    // Execute the test case
    asm("lfence\n"
        ".quad "STRINGIFY(MAGIC_BYTES_CODE)
        "\nmfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Reload
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(
        "mov r15, r14\n" \
        "add r15, 0\n" \
        RELOAD("r15", "rbx", "r13", "r11"));

    epilogue();
}