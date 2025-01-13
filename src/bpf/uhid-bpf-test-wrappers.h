/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024 Benjamin Tissoires
 */

#ifndef __UHID_BPF_TEST_WRAPPERS_H
#define __UHID_BPF_TEST_WRAPPERS_H

#include <bpf/bpf_tracing.h>

#undef bpf_printk
#include <stdio.h>
#define bpf_printk(fmt, args...) printf(fmt "\n", ##args)

/* BPF_PROG is a macro that creates the function with only
 * a context as an argument, and deal with the extra parameters
 * through some bpf magic. For testing, make it simple
 */
#undef BPF_PROG
#define BPF_PROG(name, args...) name(args)

#endif /* __UHID_BPF_TEST_WRAPPERS_H */
