/// Intel x86 Executor.
/// File: Main header
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

#ifndef REVIZOR_H
#define REVIZOR_H

#include <linux/module.h>
#include <linux/sort.h>

#include <cpuid.h>

#define print_error(...) pr_debug(__VA_ARGS__)
#define print_user_verbose(...) pr_debug(__VA_ARGS__)
#define nb_strtoul(s, base, res) kstrtoul(s, base, res)

// How many times the measurement will be repeated.
extern long warm_up_count;
#define WARM_UP_COUNT_DEFAULT 1

extern long n_inputs;
#define N_INPUTS_DEFAULT 10;

// By default, the code to be benchmarked is aligned to 64 bytes.
// This parameter allows to specify an offset to this alignment.
extern size_t alignment_offset;
#define ALIGNMENT_OFFSET_DEFAULT 0;

// Whether to generate a breakpoint trap after executing the code to be benchmarked.
extern int debug;
#define DEBUG_DEFAULT 0;

// List of inputs
extern uint64_t *inputs;
extern uint64_t current_input;
#define DEFAULT_INPUT 0;
extern uint64_t input_mask;
#define DEFAULT_INPUT_MASK 0xffffffff;

extern char *code;
extern size_t code_length;


// Pointers to the memory regions that are writable and executable.
extern char *runtime_code;

#define RUNTIME_R_SIZE (1024*1024)

// During measurements, R14, RBP, and RSP will contain these addresses plus RUNTIME_R_SIZE/2.
// If r14_size is set in the kernel module, R14 will not have this offset.
extern void *runtime_r14;
extern void *runtime_rbp;
extern void *runtime_rsp;

// Stores HTrace value during measurements
#define HTRACE_WIDTH 1
extern int64_t latest_htrace[HTRACE_WIDTH];

// Stores all measured HTraces
extern int64_t *measurement_results[HTRACE_WIDTH];

// Stores the RSP during measurements.
extern void *RSP_mem;

// Configuration Variables
extern char ssbp_patch_control;
extern char pre_run_flush;
extern char *measurement_template;

void parse_counter_configs(void);

void load_template(char *measurement_template);

int measurement(struct seq_file *output_file,
                size_t code_offset,
                size_t runtime_code_base_memory_size,
                char *runtime_code_base);

void template_l1d_prime_probe(void);
void template_l1d_flush_reload(void);
void template_l1d_prime_reload(void);

#define ENABLE_ABIT_ASSIST 1

#endif
