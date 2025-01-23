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

/* below are BPF helpers: they are stored as an enum and
 * directly called as if it were their address.
 * This works in BPF because the bpf target knows about them,
 * but in plain C, we consider them to be a function, and we
 * crash.
 *
 * We do a 2 steps operation:
 * - first we mask the helper name
 * - then we define and extern function, which needs to be
 *   properly defined in test-wrapper.c
 */

#define bpf_map_lookup_elem bpf_map_lookup_elem__hid_bpf
extern void *bpf_map_lookup_elem(void *map, const void *key);

#endif /* __UHID_BPF_TEST_WRAPPERS_H */
