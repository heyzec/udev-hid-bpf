// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Red Hat, Inc.
 */

#include <stdio.h>
#include <vmlinux.h>

static struct test_callbacks {
	int (*hid_bpf_allocate_context)(struct test_callbacks *callbacks, unsigned int hid);
	void (*hid_bpf_release_context)(struct test_callbacks *callbacks, void* ctx);
	int (*hid_bpf_hw_request)(struct test_callbacks *callbacks,
				  struct hid_bpf_ctx *ctx,
				  uint8_t *data,
				  size_t buf__sz,
				  int type,
				  int reqtype);
	int (*hid_bpf_hw_output_report)(struct test_callbacks *callbacks,
					struct hid_bpf_ctx *ctx,
					__u8 *buf, size_t buf__sz);
	/* The data returned by hid_bpf_get_data */
	uint8_t *hid_bpf_data;
	size_t hid_bpf_data_sz;
	/* The data returned by hid_bpf_allocate_context */
	struct hid_bpf_ctx *ctx;
	/* meaningful in python only */
	void *private_data;
} callbacks;

void set_callbacks(struct test_callbacks *cb)
{
	callbacks = *cb;
}

uint8_t* hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, size_t sz)
{
	/* we are not relying on ctx->allocated_size because the
	 * value might be overwritten by the bpf program (though
	 * arguably the value is read only in the kernel)
	 */
	if (offset + sz <= callbacks.hid_bpf_data_sz)
		return callbacks.hid_bpf_data + offset;
	else
		return NULL;
}

void* hid_bpf_allocate_context(unsigned int hid)
{
	int ret = callbacks.hid_bpf_allocate_context(&callbacks, hid);

	if (ret)
		return NULL;

	return callbacks.ctx;
}

void hid_bpf_release_context(void* ctx)
{
	callbacks.hid_bpf_release_context(&callbacks, ctx);
}


int hid_bpf_hw_request(struct hid_bpf_ctx *ctx,
		       uint8_t *data,
		       size_t buf__sz,
		       int type,
		       int reqtype)
{
	return callbacks.hid_bpf_hw_request(&callbacks, ctx, data, buf__sz, type, reqtype);
}

int hid_bpf_hw_output_report(struct hid_bpf_ctx *ctx,
			     __u8 *buf, size_t buf__sz)
{
	return callbacks.hid_bpf_hw_output_report(&callbacks, ctx, buf, buf__sz);
}

int bpf_wq_set_callback_impl(struct bpf_wq *wq,
		int (callback_fn)(void *map, int *key, struct bpf_wq *wq),
		unsigned int flags__k, void *aux__ign)
{
	return 0;
}
