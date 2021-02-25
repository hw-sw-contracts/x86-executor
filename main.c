/// Intel x86 Executor.
/// File: Kernel module interface
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include "linux/sysfs.h"
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <../arch/x86/include/asm/fpu/api.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 6)
#include <../arch/x86/include/asm/io.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 12, 0)
#include <asm/cacheflush.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
int (*set_memory_x)(unsigned long, int) = 0;
int (*set_memory_nx)(unsigned long, int) = 0;
#else
#include <linux/set_memory.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oleksii Oleksenko");

#include "x86-executor.h"

#define KMALLOC_MAX (4*1024*1024)  // 4 Mb is the maximum that kmalloc supports on my machines

char already_measured = 1;
unsigned inputs_top = 0;
static struct kobject *nb_kobject;

static int check_cpuid(void);
static int read_file_into_buffer(const char *file_name,
                                 char **buf,
                                 size_t *buf_len,
                                 size_t *buf_memory_size);
static int show(struct seq_file *m, void *v);
static int open(struct inode *inode, struct file *file);
static ssize_t dummy_show(struct kobject *k, struct kobj_attribute *a, char *b);
static ssize_t dummy_store(struct kobject *k, struct kobj_attribute *a, const char *b, size_t c);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 6)
static const struct proc_ops proc_file_fops = {
        .proc_lseek = seq_lseek,
        .proc_open = open,
        .proc_read = seq_read,
        .proc_release = single_release,
};
#else
static const struct file_operations proc_file_fops = {
    .llseek = seq_lseek,
    .open = open,
    .owner = THIS_MODULE,
    .read = seq_read,
    .release = single_release,
};
#endif

// ====================================================
// Globals
// ====================================================
long n_inputs = N_INPUTS_DEFAULT;
long warm_up_count = WARM_UP_COUNT_DEFAULT;
size_t alignment_offset = ALIGNMENT_OFFSET_DEFAULT;

int debug = DEBUG_DEFAULT;

char *code = NULL;
size_t code_length = 0;

char *runtime_code;
void *runtime_r14;
void *runtime_rbp;
void *runtime_rsp;
int64_t latest_htrace[HTRACE_WIDTH];
void *RSP_mem;

int64_t *measurement_results[HTRACE_WIDTH];

uint64_t *inputs;
uint64_t current_input = DEFAULT_INPUT;
uint64_t input_mask = DEFAULT_INPUT_MASK;

char *runtime_code_base = NULL;

size_t code_offset = 0;
size_t code_memory_size = 0;
size_t runtime_code_base_memory_size = 0;

// Configuration Variables
char ssbp_patch_control = 0b011;
char pre_run_flush = 1;
char *measurement_template = (char *) &template_l1d_flush_reload;

// ====================================================
// Pseudo-file system interface to the kernel module
// ====================================================
/* warning! need write-all permission so overriding check */
#undef VERIFY_OCTAL_PERMISSIONS
#define VERIFY_OCTAL_PERMISSIONS(perms) (perms)

/// Loading a test case
///
static ssize_t code_store(struct kobject *kobj,
                          struct kobj_attribute *attr,
                          const char *buf,
                          size_t count) {
    read_file_into_buffer(buf, &code, &code_length, &code_memory_size);
    return count;
}
static struct kobj_attribute code_attribute = __ATTR(code, 0660, dummy_show, code_store);

/// Loading inputs
/// Because of buffering in sysfs, this function may be called several times for
/// the same sequence of inputs
///
static ssize_t inputs_store(struct kobject *kobj,
                            struct kobj_attribute *attr,
                            const char *buf,
                            size_t count) {
    unsigned batch_size = count / 8; // inputs are 8 byte long

    // first, check for overflows
    if (inputs_top + batch_size > n_inputs) {
        //printk(KERN_ERR "Loading too many inputs %d %lu\n", inputs_top + batch_size, n_inputs);
        n_inputs = 0;
        return count;
    }
    if (!inputs) {
        printk(KERN_ERR "Did not allocate memory for inputs\n");
        return count;
    }

    // load the batch
    uint64_t *new_inputs = (uint64_t *) buf;
    for (unsigned i = 0; i < batch_size; i++) {
        inputs[inputs_top + i] = new_inputs[i];
    }
    inputs_top += batch_size;
    return count;
}
static struct kobj_attribute inputs_attribute = __ATTR(inputs, 0666, dummy_show, inputs_store);

/// Changing the number of tested inputs
///
static ssize_t n_inputs_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", n_inputs);
}
static ssize_t n_inputs_store(struct kobject *kobj,
                              struct kobj_attribute *attr,
                              const char *buf,
                              size_t count) {
    inputs_top = 0;  // restart input loading
    unsigned long old_n_inputs = n_inputs;
    sscanf(buf, "%ld", &n_inputs);

    if (old_n_inputs < n_inputs) {
        // allocate more memory for measurements
        for (int i = 0; i < HTRACE_WIDTH; i++) {
            kfree(measurement_results[i]);
            measurement_results[i] = kmalloc(n_inputs * sizeof(int64_t), GFP_KERNEL);
            if (!measurement_results[i]) {
                printk(KERN_ERR "Could not allocate memory for measurement_results\n");
                return 0;
            }
            memset(measurement_results[i], 0, n_inputs * sizeof(int64_t));
        }

        // and for inputs
        kfree(inputs);
        inputs = kmalloc(n_inputs * sizeof(int64_t), GFP_KERNEL);
        if (!inputs) {
            printk(KERN_ERR "Could not allocate memory for prng_seeds\n");
            return -1;
        }
    }
    return count;
}
static struct kobj_attribute n_inputs_attribute =
        __ATTR(n_inputs, 0666, n_inputs_show, n_inputs_store);

/// Setting a mask for randomly generated values
///
static ssize_t input_mask_store(struct kobject *kobj,
                              struct kobj_attribute *attr,
                              const char *buf,
                              size_t count) {
    sscanf(buf, "%llu", &input_mask);
    return count;
}
static struct kobj_attribute input_mask_attribute =
        __ATTR(input_mask, 0666, dummy_show, input_mask_store);

/// Setting the number of warm up rounds
///
static ssize_t warmups_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%ld\n", warm_up_count);
}
static ssize_t warmups_store(struct kobject *kobj,
                             struct kobj_attribute *attr,
                             const char *buf,
                             size_t count) {
    sscanf(buf, "%ld", &warm_up_count);
    return count;
}
static struct kobj_attribute warmups_attribute = __ATTR(warmups, 0666, warmups_show, warmups_store);

/// Getting the base address of the sandbox
///
static ssize_t print_sandbox_base_show(struct kobject *kobj,
                                       struct kobj_attribute *attr,
                                       char *buf) {
    return sprintf(buf, "%llx\n", (long long unsigned) runtime_r14 - RUNTIME_R_SIZE / 2);
}

static struct kobj_attribute
        print_sandbox_base_attribute =
        __ATTR(print_sandbox_base, 0664, print_sandbox_base_show, dummy_store);

/// Getting the base address of the stack
///
static ssize_t print_stack_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%llx\n", (long long unsigned) runtime_rsp - RUNTIME_R_SIZE / 2);
}

static struct kobj_attribute
        print_stack_base_attribute =
        __ATTR(print_stack_base, 0664, print_stack_base_show, dummy_store);

/// Getting the base address of the memory region where the test case is loaded
///
static ssize_t print_code_base_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%llx\n", (long long unsigned) runtime_code);
}

static struct kobj_attribute
        print_code_base_attribute =
        __ATTR(print_code_base, 0664, print_code_base_show, dummy_store);

/// Getting the offset from the base of the memory region where the test case is loaded
///
static ssize_t code_offset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%zu\n", code_offset);
}
static ssize_t code_offset_store(struct kobject *kobj,
                                 struct kobj_attribute *attr,
                                 const char *buf,
                                 size_t count) {
    sscanf(buf, "%zu", &code_offset);
    return count;
}
static struct kobj_attribute
        code_offset_attribute = __ATTR(code_offset, 0660, code_offset_show, code_offset_store);

/// Reset the experiment
///
static ssize_t reset_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    n_inputs = N_INPUTS_DEFAULT;
    inputs[0] = DEFAULT_INPUT;
    code_length = 0;
    code_offset = 0;
    return 0;
}

static struct kobj_attribute reset_attribute = __ATTR(reset, 0664, reset_show, dummy_store);

/// SSBP patch
///
static ssize_t enable_ssbp_patch_store(struct kobject *kobj,
                                       struct kobj_attribute *attr,
                                       const char *buf,
                                       size_t count) {
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    ssbp_patch_control = (value == 0) ? 0b011 : 0b111;
    return count;
}
static struct kobj_attribute
        enable_ssbp_patch_attribute =
        __ATTR(enable_ssbp_patch, 0666, dummy_show, enable_ssbp_patch_store);

/// Flushing before measurements
///
static ssize_t enable_pre_run_flush_store(struct kobject *kobj,
                                          struct kobj_attribute *attr,
                                          const char *buf,
                                          size_t count) {
    unsigned value = 0;
    sscanf(buf, "%u", &value);
    pre_run_flush = (value == 0) ? 0 : 1;
    return count;
}
static struct kobj_attribute
        enable_pre_run_flush_attribute =
        __ATTR(enable_pre_run_flush, 0666, dummy_show, enable_pre_run_flush_store);

/// Measurement template selector
///
static ssize_t measurement_mode_store(struct kobject *kobj,
                                      struct kobj_attribute *attr,
                                      const char *buf,
                                      size_t count) {
    if (buf[0] == 'F') {
        measurement_template = (char *) &template_l1d_flush_reload;
    } else if (buf[0] == 'P') {
        if (buf[2] == 'R') {
            measurement_template = (char *) &template_l1d_prime_reload;
        } else {
            measurement_template = (char *) &template_l1d_prime_probe;
        }
    }
    return count;
}
static struct kobj_attribute
        measurement_mode_attribute =
        __ATTR(measurement_mode, 0666, dummy_show, measurement_mode_store);

// ====================================================
// Module's constructor and destructor
// ====================================================
static int __init nb_init(void) {
    pr_debug("Initializing x86-executor kernel module...\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
    set_memory_x = (void *) kallsyms_lookup_name("set_memory_x");
    set_memory_nx = (void *) kallsyms_lookup_name("set_memory_nx");
#endif
    if (check_cpuid()) {
        return -1;
    }

    // Memory for traces
    for (int i = 0; i < HTRACE_WIDTH; i++) {
        measurement_results[i] = kmalloc(n_inputs * sizeof(int64_t), GFP_KERNEL);
        if (!measurement_results[i]) {
            printk(KERN_ERR "Could not allocate memory for measurement_results\n");
            return -1;
        }
        memset(measurement_results[i], 0, n_inputs * sizeof(int64_t));
    }

    // Memory for inputs
    inputs = kmalloc(n_inputs * sizeof(int64_t), GFP_KERNEL);
    if (!inputs) {
        printk(KERN_ERR "Could not allocate memory for inputs\n");
        return -1;
    }
    inputs[0] = DEFAULT_INPUT;

    // Memory for sandbox and stack
    runtime_r14 = vmalloc(RUNTIME_R_SIZE);     // vmalloc addresses are page aligned
    runtime_rsp = vmalloc(RUNTIME_R_SIZE);
    if (!runtime_r14 || !runtime_rsp) {
        printk(KERN_ERR "Could not allocate memory for runtime_r*\n");
        return -1;
    }
    runtime_r14 += RUNTIME_R_SIZE / 2;
    runtime_rsp += RUNTIME_R_SIZE / 2;
    runtime_rbp = runtime_rsp;

    // Memory for the test case's code
    runtime_code_base = kmalloc(KMALLOC_MAX, GFP_KERNEL);
    if (!runtime_code_base) {
        printk(KERN_ERR "Could not allocate memory for runtime_code\n");
        return -1;
    }
    runtime_code_base_memory_size = KMALLOC_MAX;
    set_memory_x((unsigned long) runtime_code_base, runtime_code_base_memory_size / PAGE_SIZE);
    runtime_code = runtime_code_base;

    // Create a pseudo file system
    nb_kobject = kobject_create_and_add("x86-executor", kernel_kobj->parent);
    if (!nb_kobject) {
        pr_debug("failed to create and add x86-executor\n");
        return -1;
    }

    int error = sysfs_create_file(nb_kobject, &reset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &code_offset_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &inputs_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &n_inputs_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &input_mask_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &warmups_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &print_sandbox_base_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &print_stack_base_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &print_code_base_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &enable_ssbp_patch_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &enable_pre_run_flush_attribute.attr);
    error |= sysfs_create_file(nb_kobject, &measurement_mode_attribute.attr);

    if (error) {
        pr_debug("failed to create file in /sys/x86-executor/\n");
        return error;
    }

    struct proc_dir_entry *proc_file_entry =
            proc_create("x86-executor", 0, NULL, &proc_file_fops);
    if (proc_file_entry == NULL) {
        pr_debug("failed to create file in /proc/\n");
        return -1;
    }

    return 0;
}

static void __exit nb_exit(void) {
    kfree(code);
    vfree(runtime_rsp - RUNTIME_R_SIZE / 2);

    if (runtime_code_base) {
        set_memory_nx((unsigned long) runtime_code_base, runtime_code_base_memory_size / PAGE_SIZE);
        kfree(runtime_code_base);
    }

    vfree(runtime_r14 - RUNTIME_R_SIZE / 2);

    kfree(inputs);

    for (int i = 0; i < HTRACE_WIDTH; i++) {
        kfree(measurement_results[i]);
    }

    kobject_put(nb_kobject);
    remove_proc_entry("x86-executor", NULL);
}

module_init(nb_init);
module_exit(nb_exit);

// ====================================================
// Helpers
// ====================================================
void build_cpuid_string(char *buf,
                        unsigned int r0,
                        unsigned int r1,
                        unsigned int r2,
                        unsigned int r3) {
    memcpy(buf, (char *) &r0, 4);
    memcpy(buf + 4, (char *) &r1, 4);
    memcpy(buf + 8, (char *) &r2, 4);
    memcpy(buf + 12, (char *) &r3, 4);
}

/// Make sure we can use this CPU
///
static int check_cpuid() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(0, eax, ebx, ecx, edx);

    char proc_vendor_string[17] = {0};
    build_cpuid_string(proc_vendor_string, ebx, edx, ecx, 0);
    print_user_verbose("Vendor ID: %s\n", proc_vendor_string);

    char proc_brand_string[48];
    __cpuid(0x80000002, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string, eax, ebx, ecx, edx);
    __cpuid(0x80000003, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string + 16, eax, ebx, ecx, edx);
    __cpuid(0x80000004, eax, ebx, ecx, edx);
    build_cpuid_string(proc_brand_string + 32, eax, ebx, ecx, edx);
    print_user_verbose("Brand: %s\n", proc_brand_string);

    __cpuid(0x01, eax, ebx, ecx, edx);
    unsigned int displ_family = ((eax >> 8) & 0xF);
    if (displ_family == 0x0F) {
        displ_family += ((eax >> 20) & 0xFF);
    }
    unsigned int displ_model = ((eax >> 4) & 0xF);
    if (displ_family == 0x06 || displ_family == 0x0F) {
        displ_model += ((eax >> 12) & 0xF0);
    }
    print_user_verbose("DisplayFamily_DisplayModel: %.2X_%.2XH\n", displ_family, displ_model);
    print_user_verbose("Stepping ID: %u\n", (eax & 0xF));

    if (strcmp(proc_vendor_string, "GenuineIntel") == 0) {
        __cpuid(0x0A, eax, ebx, ecx, edx);
        unsigned int perf_mon_ver = (eax & 0xFF);
        print_user_verbose("Performance monitoring version: %u\n", perf_mon_ver);
        if (perf_mon_ver < 2) {
            print_error("Error: performance monitoring version >= 2 required\n");
            return 1;
        }

        print_user_verbose("Bit widths of general-purpose performance counters: %u\n",
                           ((eax >> 16) & 0xFF));

    } else {
        print_error("Error: unsupported CPU found\n");
        return 1;
    }

    return 0;
}

static int read_file_into_buffer(const char *file_name,
                                 char **buf,
                                 size_t *buf_len,
                                 size_t *buf_memory_size) {
    struct file *filp = NULL;
    filp = filp_open(file_name, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_debug("Error opening file %s\n", file_name);
        return -1;
    }

    struct path p;
    struct kstat ks;
    kern_path(file_name, 0, &p);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0)
    if (vfs_getattr(&p, &ks)) {
#else
    if (vfs_getattr(&p, &ks, 0, 0)) {
#endif
        pr_debug("Error getting file attributes\n");
        return -1;
    }

    size_t file_size = ks.size;
    *buf_len = file_size;

    if (file_size + 1 > *buf_memory_size) {
        kfree(*buf);
        *buf_memory_size = max(2 * (file_size + 1), PAGE_SIZE);
        *buf = kmalloc(*buf_memory_size, GFP_KERNEL);
        if (!*buf) {
            printk(KERN_ERR
                   "Could not allocate memory for %s\n", file_name);
            *buf_memory_size = 0;
            filp_close(filp, NULL);
            return -1;
        }
    }

    loff_t pos = 0;
    kernel_read(filp, *buf, file_size, &pos);
    (*buf)[file_size] = '\0';

    path_put(&p);
    filp_close(filp, NULL);
    return 0;
}

void report(struct seq_file *output_file) {
    // CSV header
    seq_printf(output_file, "CACHE_MAP\n");

    // measurements
    for (int i = 0; i < n_inputs; i++) {
        seq_printf(output_file, "%llu\n", measurement_results[0][i]);
    }
}

static int show(struct seq_file *m, void *v) {
    if (already_measured == 0) {
        measurement(m, code_offset, runtime_code_base_memory_size, runtime_code_base);
        report(m);
        already_measured = 1;
    } else {
        report(m);
    }
    return 0;
}

static int open(struct inode *inode, struct file *file) {
    already_measured = 0;
    return single_open(file, show, NULL);
}

/// Empty functions for those actions where store/show are not necessary
///
static ssize_t dummy_show(struct kobject *k, struct kobj_attribute *a, char *b) {
    return 0;
}
static ssize_t dummy_store(struct kobject *k, struct kobj_attribute *a, const char *b, size_t c) {
    return 0;
}
