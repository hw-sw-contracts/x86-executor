/// Intel x86 Executor.
/// File:
///  - Test case execution
///  - Ensuring an isolated environment
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

#include <linux/seq_file.h>
#include <linux/irqflags.h>
#include <../arch/x86/include/asm/fpu/api.h>
#include <../arch/x86/include/asm/pgtable.h>
#include <../arch/x86/include/asm/tlbflush.h>

#include "x86-executor.h"

#ifndef MSR_IA32_PMC0
#define MSR_IA32_PMC0               0x0C1
#endif
#ifndef MSR_IA32_PERFEVTSEL0
#define MSR_IA32_PERFEVTSEL0        0x186
#endif
#ifndef MSR_OFFCORE_RSP0
#define MSR_OFFCORE_RSP0            0x1A6
#endif
#ifndef MSR_OFFCORE_RSP1
#define MSR_OFFCORE_RSP1            0x1A7
#endif
#ifndef MSR_IA32_FIXED_CTR0
#define MSR_IA32_FIXED_CTR0         0x309
#endif
#ifndef MSR_IA32_FIXED_CTR_CTRL
#define MSR_IA32_FIXED_CTR_CTRL     0x38D
#endif
#ifndef MSR_IA32_PERF_GLOBAL_CTRL
#define MSR_IA32_PERF_GLOBAL_CTRL   0x38F
#endif

struct pfc_config {
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};


unsigned long assist_page_addr;
pte_t assist_page_pte;
pte_t *assist_page_ptep;

void write_msr(unsigned int msr, uint64_t value);
void config_pfc(unsigned int id, char *pfc_code, unsigned int usr, unsigned int os);
size_t get_required_runtime_code_length(void);
pte_t *get_pte(unsigned long address);

// ====================================================
// Measurement
// ====================================================
static inline void pre_measurement_setup(void) {
    // on some microarchitectures (e.g., Broadwell), some events
    // (e.g., L1 misses) are not counted properly if only the OS field is set
    config_pfc(0, "D1.01", 1, 1);             // L1 hits - for htrace collection
    config_pfc(1, "C3.01.CMSK=1.EDG", 1, 1);  // machine clears - fuzzing feedback
    config_pfc(2, "C5.00", 1, 1);             // mispredicted branches - fuzzing feedback
    config_pfc(3, "0E.01", 1, 1);             // unused

    write_msr(MSR_IA32_SPEC_CTRL, ssbp_patch_control);

    assist_page_addr = (unsigned long) runtime_r14 + 4096;
    assist_page_ptep = get_pte(assist_page_addr);
    if (assist_page_ptep == NULL) {
        printk(KERN_ERR "pre_measurement_setup: Couldn't get the sandbox pte entry");
        return;
    }
}

static inline void single_run(long i, int64_t *results[]) {
    // ignore "warm-up" runs (i<0)
    long i_ = (i < 0) ? 0 : i;
    current_input = inputs[i_];
    // MG-TODO: Select current deps, current delta_input, ... 
    bool overwrite = i_ >= deltas_threshold && enabled_deltas;
    if (overwrite) {
        printk(KERN_ERR "Init overwrite\n");
        // MG-TODO: declare current_delta_input
        printk(KERN_ERR "index %ld", i_ - deltas_threshold);
        current_delta_input = delta_inputs[i_ - deltas_threshold];
        printk(KERN_ERR "Current delta input %llu\n", current_delta_input);

        // MG-TODO: declare current_deps_pos (unsigned char)
        // MG-TODO: declare the correct variables  
        current_deps_length = deps[current_deps_pos];
        printk(KERN_ERR "Current deps length %u", current_deps_length);
        current_deps_pos += 1;
        printk(KERN_ERR "Current pos %u", current_deps_pos);
        if (current_deps_length > 0) 
            current_deps = deps[current_deps_pos];
        else 
            overwrite = false; // if there are no deps information
    }
    else
        printk(KERN_ERR "Initial overwrite is false!");




    if (pre_run_flush == 1) {
        static const u16 ds = __KERNEL_DS;
        asm volatile("verw %[ds]" : : [ds] "m"(ds) : "cc");
        write_msr(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
    }

    // initialize the "stack" with zeroes
    unsigned long stack_base = (unsigned long) runtime_rsp;
    for (int j = -1024; j < 1024; j += 1) {
        ((uint32_t *) stack_base)[j] = 0;
    }

    // initialize eviction region with zeroes
    unsigned long eviction_region = (unsigned long) runtime_r14 - 36864;
    for (int j = 0; j < 8192; j += 1) {
        ((uint32_t *) eviction_region)[j] = 0;
    }

    // initialize memory: sandbox page, assist page, and two pages around them (for overflows)
    unsigned long initialized_memory_base = (unsigned long) runtime_r14 - 4096;
    uint64_t random_value = current_input;
    uint64_t masked_rvalue;
    for (int j = 0; j < 4096; j += 1) {
        random_value = (((random_value * 2891336453) % 0x100000000) + 12345) % 0x100000000;
        masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask;
        masked_rvalue = masked_rvalue << 6;
        ((uint32_t *) initialized_memory_base)[j] = masked_rvalue;
    }
    current_input = random_value;

    if (overwrite){
        printk(KERN_ERR "Beginning overwrite");
        uint64_t random_delta_value = current_delta_input;
        uint64_t masked_rvalue;
        for (int j = 0; j < 4096; j += 1) {
            printk(KERN_ERR "current_deps[0] %u", current_deps[0]);
            // Initialize the new value
            random_delta_value = (((random_delta_value * 2891336453) % 0x100000000) + 12345) % 0x100000000;
            masked_rvalue = (random_delta_value ^ (random_delta_value >> 16)) & input_mask;
            masked_rvalue = masked_rvalue << 6;

            bool flag = current_deps_length == 0 || current_deps[0] < (initialized_memory_base + 4 * j) || current_deps[0] >= initialized_memory_base + 4 * (j+1);
            if (flag) {
                // if flag holds, then the current 4 bytes are not involved in
                // one of the dependencies that should be preserved
                ((uint32_t *) initialized_memory_base)[j] = masked_rvalue;
            }
            else {
                // the current 4 bytes involve some of the addresses in the
                // memory dependency (length > 0 and current_deps[0] in the
                // interval)
                
                // 1. look for all further dependencies in deps that also fit into the interval.
                // We migth have more than 1 address (at most 4)
                // 2. Here we also increment current_deps correctly!
                uint64_t addrs [4] ={0, 0, 0, 0};

                for (int idx=0; idx < 4; idx++)
                    if (current_deps_length > 0)
                        if (current_deps[idx] < initialized_memory_base + 4 * (j+1) )
                        {
                            // we're still in the interval
                            addrs[idx] = current_deps[idx];
                            current_deps_length -= 1;
                            current_deps_pos += 4; // each address is 4 bytes!
                        }

                bool toPreserve[4] = {0,0,0,0};
                for(int idx =0; idx < 4; idx++){
                    if(addrs[idx] != 0 && addrs[idx] == (initialized_memory_base + (4 * j) + idx))
                        toPreserve[idx] = 1;
                }

                union {
                    uint32_t double_word;
                    uint8_t octets[4];
                } toWrite;
                 union {
                    uint32_t double_word;
                    uint8_t octets[4];
                } old;
                toWrite.double_word = masked_rvalue;
                old.double_word = ((uint32_t *) initialized_memory_base)[j];

                for(int idx = 0; idx < 4; idx++)
                    if (toPreserve[idx])
                        toWrite.octets[idx] = old.octets[idx];

                ((uint32_t *) initialized_memory_base)[j] = toWrite.double_word;
            }
        }
    }

    // clear the ACCESSED bit and flush the corresponding TLB entry
    if (enable_mds_page) {
        assist_page_pte.pte = assist_page_ptep->pte & ~_PAGE_ACCESSED;
        set_pte_at(current->mm, assist_page_addr, assist_page_ptep, assist_page_pte);
        asm volatile("clflush (%0)\nlfence\n"::"r" (assist_page_addr) : "memory");
        asm volatile("invlpg (%0)"::"r" (assist_page_addr) : "memory");
    }

    // execute
    ((void (*)(void)) runtime_code)();

    // store the measurement results
    results[0][i_] = latest_htrace[0];
    results[1][i_] = latest_pfc_readings[0];
    results[2][i_] = latest_pfc_readings[1];
    results[3][i_] = latest_pfc_readings[2];
}

void run_experiment(int64_t *results[]) {
    get_cpu();
    unsigned long flags;
    raw_local_irq_save(flags);

    for (long i = -warm_up_count; i < n_inputs; i++) {
        single_run(i, results);
    }

    raw_local_irq_restore(flags);
    put_cpu();
}

int measurement(struct seq_file *output_file,
                size_t code_offset,
                size_t runtime_code_base_memory_size,
                char *runtime_code_base) {
    // Prepare for the experiment:
    // 1. Ensure that all necessary objects are allocated
    for (int i = 0; i < HTRACE_WIDTH; i++) {
        if (!measurement_results[i]) {
            printk(KERN_ERR "Did not allocate memory for measurement_results\n");
            return -1;
        }
    }
    if (!inputs) {
        printk(KERN_ERR "Did not allocate memory for inputs\n");
        return -1;
    }

    size_t req_code_length = code_offset + get_required_runtime_code_length();
    if (req_code_length > runtime_code_base_memory_size) {
        printk(KERN_ERR
               "Maximum supported code size %zu kB; requested %zu kB\n",
               runtime_code_base_memory_size / 1024,
               req_code_length / 1024);
        return -1;
    }
    runtime_code = runtime_code_base + code_offset;

    // 2. Enable FPU - just in case, we might use it within the test case
    kernel_fpu_begin();

    // 3. Select a template
    load_template(measurement_template);

    // 4. Run the measurement
    pre_measurement_setup();
    run_experiment(measurement_results);

    kernel_fpu_end();
    return 0;
}

// ====================================================
// Helper Functions
// ====================================================
void write_msr(unsigned int msr, uint64_t value) {
    native_write_msr(msr, (uint32_t) value, (uint32_t)(value >> 32));
}

/// Clears the programmable performance counters and writes the
/// configurations to the corresponding MSRs.
void config_pfc(unsigned int id, char *pfc_code, unsigned int usr, unsigned int os) {
    // Parse the PFC code name
    struct pfc_config config = {0};

    char buf[50];
    strcpy(buf, pfc_code);

    char *tok = buf;

    char *evt_num = strsep(&tok, ".");
    nb_strtoul(evt_num, 16, &(config.evt_num));

    char *umask = strsep(&tok, ".");
    nb_strtoul(umask, 16, &(config.umask));

    char *ce;
    while ((ce = strsep(&tok, ".")) != NULL) {
        if (!strcmp(ce, "AnyT")) {
            config.any = 1;
        } else if (!strcmp(ce, "EDG")) {
            config.edge = 1;
        } else if (!strcmp(ce, "INV")) {
            config.inv = 1;
        } else if (!strncmp(ce, "CMSK=", 5)) {
            nb_strtoul(ce + 5, 0, &(config.cmask));
        }
    }

    // Configure the counter
    uint64_t global_ctrl = native_read_msr(MSR_IA32_PERF_GLOBAL_CTRL);
    global_ctrl |= ((uint64_t) 7 << 32) | 15;
    write_msr(MSR_IA32_PERF_GLOBAL_CTRL, global_ctrl);

    uint64_t perfevtselx = native_read_msr(MSR_IA32_PERFEVTSEL0 + id);

    // disable the counter
    perfevtselx &= ~(((uint64_t) 1 << 32) - 1);
    write_msr(MSR_IA32_PERFEVTSEL0 + id, perfevtselx);

    // clear
    write_msr(MSR_IA32_PMC0 + id, 0);

    // configure counter
    perfevtselx |= ((config.cmask & 0xFF) << 24);
    perfevtselx |= (config.inv << 23);
    perfevtselx |= (1ULL << 22);
    perfevtselx |= (config.any << 21);
    perfevtselx |= (config.edge << 18);
    perfevtselx |= (os << 17);
    perfevtselx |= (usr << 16);
    perfevtselx |= ((config.umask & 0xFF) << 8);
    perfevtselx |= (config.evt_num & 0xFF);
    write_msr(MSR_IA32_PERFEVTSEL0 + id, perfevtselx);
}

size_t get_required_runtime_code_length() {
    size_t req_code_length = code_length + alignment_offset + 64;
    return 2 * req_code_length + 10000;
}

pte_t *get_pte(unsigned long address) {
    pgd_t * pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    /* Make sure we are in vmalloc area: */
    if (!(address >= VMALLOC_START && address < VMALLOC_END))
        return NULL;

    pgd = pgd_offset(current->mm, address);
    if (pgd_none(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, address);
    pud = pud_offset(p4d, address);
    if (pud_none(*pud))
        return NULL;

    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd))
        return NULL;

    pte = pte_offset_kernel(pmd, address);
    if (!pte_present(*pte))
        return NULL;

    return pte;
}