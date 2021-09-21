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

// Pointers to the memory regions that are writable and executable.
extern char *runtime_code;

#define WORKING_MEMORY_SIZE (1024*1024)
#define MAIN_REGION_SIZE 4096
#define ASSIST_REGION_SIZE 4096
#define EVICT_REGION_SIZE (8 * 4096)
#define OVERFLOW_REGION_SIZE 4096
#define REG_INITIALIZATION_REGION_SIZE 64

// Base addresses for the main memory regions
extern void *sandbox_base;
extern void *upper_overflow_base;
extern void *assist_base;
extern void *stack_base;
extern void *main_base;
extern void *register_initialization_base;
extern void *lower_overflow_base;
extern void *eviction_base;

// List of inputs
#define TMP_MIGRATION 1
#if TMP_MIGRATION == 1
#define INPUT_SIZE (MAIN_REGION_SIZE + ASSIST_REGION_SIZE)
#else
#define INPUT_SIZE 1
#endif
extern uint64_t *inputs;

extern char *code;
extern size_t code_length;

// Stores HTrace value during measurements
#define HTRACE_WIDTH 1
extern int64_t latest_htrace[HTRACE_WIDTH];

// Stores PFC readings during measurements
#define NUM_PFC 3
extern int64_t latest_pfc_readings[NUM_PFC];

// Stores all measured HTraces
#define NUM_MEASUREMENT_FIELDS (HTRACE_WIDTH+NUM_PFC)
extern int64_t *measurement_results[NUM_MEASUREMENT_FIELDS];

// Stores the RSP during measurements.
extern void *RSP_mem;

// Configuration Variables
extern char ssbp_patch_control;
extern char enable_assist_page;
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
void template_l1d_evict_reload(void);

#endif
