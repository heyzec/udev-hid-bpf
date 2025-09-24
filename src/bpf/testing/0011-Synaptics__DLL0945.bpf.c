// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Red Hat, Inc */

/*
 * Fix for Synaptics DLL0945:00 06CB:CE26 touchpad that forgets to send
 * release events for fingers when multiple contacts are used.
 *
 * The device sometimes fails to properly report finger lift events
 * when transitioning from multiple contacts to fewer contacts or no contacts.
 * This BPF program tracks the state of each contact and synthesizes
 * missing release events.
 *
 * Report ID 3 (Touch) structure from HID report descriptor:
 *
 * ...
 * 0x05, 0x0d,                    // Usage Page (Digitizers)             50
 * 0x09, 0x05,                    // Usage (Touch Pad)                   52
 * 0xa1, 0x01,                    // Collection (Application)            54
 * 0x85, 0x03,                    //  Report ID (3)                      56
 * 0x05, 0x0d,                    //  Usage Page (Digitizers)            58
 * 0x09, 0x22,                    //  Usage (Finger)                     60
 * 0xa1, 0x02,                    //  Collection (Logical)               62
 * 0x15, 0x00,                    //   Logical Minimum (0)               64
 * 0x25, 0x01,                    //   Logical Maximum (1)               66
 * 0x09, 0x47,                    //   Usage (Confidence)                68
 * 0x09, 0x42,                    //   Usage (Tip Switch)                70
 * 0x95, 0x02,                    //   Report Count (2)                  72
 * 0x75, 0x01,                    //   Report Size (1)                   74
 * 0x81, 0x02,                    //   Input (Data,Var,Abs)              76
 * 0x95, 0x01,                    //   Report Count (1)                  78
 * 0x75, 0x03,                    //   Report Size (3)                   80
 * 0x25, 0x05,                    //   Logical Maximum (5)               82
 * 0x09, 0x51,                    //   Usage (Contact Id)                84
 * 0x81, 0x02,                    //   Input (Data,Var,Abs)              86
 * 0x75, 0x01,                    //   Report Size (1)                   88
 * 0x95, 0x03,                    //   Report Count (3)                  90
 * 0x81, 0x03,                    //   Input (Cnst,Var,Abs)              92
 * 0x05, 0x01,                    //   Usage Page (Generic Desktop)      94
 * 0x15, 0x00,                    //   Logical Minimum (0)               96
 * 0x26, 0x45, 0x05,              //   Logical Maximum (1349)            98
 * 0x75, 0x10,                    //   Report Size (16)                  101
 * 0x55, 0x0e,                    //   Unit Exponent (-2)                103
 * 0x65, 0x11,                    //   Unit (SILinear: cm)               105
 * 0x09, 0x30,                    //   Usage (X)                         107
 * 0x35, 0x00,                    //   Physical Minimum (0)              109
 * 0x46, 0x64, 0x04,              //   Physical Maximum (1124)           111
 * 0x95, 0x01,                    //   Report Count (1)                  114
 * 0x81, 0x02,                    //   Input (Data,Var,Abs)              116
 * 0x46, 0xa2, 0x02,              //   Physical Maximum (674)            118
 * 0x26, 0x29, 0x03,              //   Logical Maximum (809)             121
 * 0x09, 0x31,                    //   Usage (Y)                         124
 * 0x81, 0x02,                    //   Input (Data,Var,Abs)              126
 * 0xc0,                          //  End Collection                     128
 * 0x05, 0x0d,                    //  Usage Page (Digitizers)            129
 * 0x09, 0x22,                    //  Usage (Finger)                     131
 * ...
 *
 * - Device supports up to 15 contacts (Contact Max = 15)
 * - Each contact: 1 byte flags + 4 bytes coordinates (5 bytes total)
 * - Flags byte: Confidence(0) | Tip Switch(1) | Contact ID(2-4) | padding(5-7)
 * - X coordinate: 2 bytes little endian (offset +1,+2)
 * - Y coordinate: 2 bytes little endian (offset +3,+4)
 * - Contact count at offset 28
 * - Total report size: 31 bytes
 *
 * Note: This implementation handles only the first 5 contacts, which covers
 * the most common use cases. The device can report up to 15 contacts but
 * handling all would significantly increase complexity.
 */

#include "vmlinux.h"
#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#define VID_SYNAPTICS		0x06CB
#define PID_DLL0945_9310	0xCDE6
#define PID_DLL0945_5406	0xCE26

/* Report ID for touch events */
#define TOUCH_REPORT_ID		3

/* Max number of contacts supported by this implementation */
#define MAX_CONTACTS		5

/* Expected report descriptor size for Synaptics DLL0945 */
#define EXPECTED_RDESC_SIZE		665

/* Packed struct representing a single touch contact in the HID report */
struct touch_contact {
	__u8 confidence:1;
	__u8 tip_switch:1;
	__u8 contact_id:3;
	__u8 padding:3;
	__u16 x;
	__u16 y;
} __attribute__((packed));

/* Packed struct representing the complete touch report (31 bytes) */
struct touch_report {
	__u8 report_id;					/* offset 0 */
	struct touch_contact contacts[MAX_CONTACTS];	/* offsets 1-25 (5 contacts × 5 bytes) */
	__u16 scan_time;				/* offsets 26-27 */
	__u8 contact_count;				/* offset 28 */
	__u8 button;					/* offset 29 */
	__u8 reserved;					/* offset 30 */
} __attribute__((packed));

/* Compact hashmap entry: combines active state and slot index in 1 byte */
struct contact_state {
	__u8 active:1;		/* bit 0: is contact active */
	__u8 slot:7;		/* bits 1-7: slot index in prev report (0-127) */
} __attribute__((packed));

/* Previous report state for contact tracking */
static struct touch_report prev_report;

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(synaptics_dll0945_device_event, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 31 /* size */);
	struct touch_report *current_report;
	struct contact_state contact_map[MAX_CONTACTS] = {};	/* Local hashmap for O(1) contact tracking */
	__u8 prev_count;
	int i;

	if (!data)
		return 0;

	/* Only process touch reports */
	if (data[0] != TOUCH_REPORT_ID)
		return 0;

	current_report = (struct touch_report *)data;

	/* Fast path: if contact count increases or equals previous, just copy and return */
	if (current_report->contact_count >= prev_report.contact_count) {
		__builtin_memcpy(&prev_report, current_report, sizeof(struct touch_report));
		return 0;
	}

	/* Contact count decreased - potential bug condition, process both reports */

	/* Calculate expected contact count: start with prev contacts, subtract releases */
	prev_count = prev_report.contact_count;

	/* Process previous report: build hashmap of active contacts and count releases */
	for (i = 0; i < MAX_CONTACTS; i++) {
		if (prev_report.contacts[i].confidence) {
			__u8 contact_id = prev_report.contacts[i].contact_id;

			if (contact_id < MAX_CONTACTS) {
				if (prev_report.contacts[i].tip_switch == 1) {
					/* This was an active (touching) contact */
					contact_map[contact_id].slot = i;
					contact_map[contact_id].active = 1;
				} else {
					/* This was a release event - decrement expected count */
					prev_count--;
				}
			}
		}
	}

	/* If expected count matches current count, no missing contacts */
	if (prev_count == current_report->contact_count) {
		__builtin_memcpy(&prev_report, current_report, sizeof(struct touch_report));
		return 0;
	}

	/* We have missing touch releases - remove current contacts from hashmap */
	for (i = 0; i < MAX_CONTACTS; i++) {
		if (current_report->contacts[i].confidence) {
			__u8 contact_id = current_report->contacts[i].contact_id;

			if (contact_id < MAX_CONTACTS)
				contact_map[contact_id].active = 0;
		}
	}

	__u16 contact_count = current_report->contact_count;

	/* Inject release events for remaining active contacts */
	for (i = 0; i < MAX_CONTACTS; i++) {
		if (contact_map[i].active && contact_count < MAX_CONTACTS) {
			/* Get original slot position */
			__u8 orig_slot = contact_map[i].slot;

			if (orig_slot >= MAX_CONTACTS)
				break; /* ensure the verifiers understands we won't get too far */

			/* Copy entire contact structure from previous report */
			__builtin_memcpy(&current_report->contacts[contact_count],
					&prev_report.contacts[orig_slot],
					sizeof(struct touch_contact));

			/* Toggle only the tip_switch bit to 0 (release) */
			current_report->contacts[contact_count].tip_switch = 0;

			contact_count++;
		}
	}

	current_report->contact_count = contact_count;

	/* Store current report for next iteration */
	__builtin_memcpy(&prev_report, current_report, sizeof(struct touch_report));

	return 0;
}

HID_BPF_OPS(synaptics_dll0945) = {
	.hid_device_event = (void *)synaptics_dll0945_device_event,
};

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	/*
	 * TEMPORARY FIX: This BPF program provides a workaround for missing
	 * finger release events on Synaptics DLL0945 touchpads until the
	 * kernel hid-multitouch driver is updated with MT_QUIRK_NOT_SEEN_MEANS_UP.
	 *
	 * Unfortunately, we cannot detect from BPF whether the kernel already
	 * has this fix, as the multitouch driver's internal structures are not
	 * accessible. This may result in redundant processing if both the kernel
	 * and BPF handle the same issue.
	 *
	 * This workaround should be removed once the upstream kernel includes
	 * the proper fix for this device.
	 */

	/* Sanity check: verify expected report descriptor size */
	ctx->retval = ctx->rdesc_size != EXPECTED_RDESC_SIZE;
	if (ctx->retval)
		ctx->retval = -EINVAL;

	return 0;
}

HID_BPF_CONFIG(
	HID_DEVICE(BUS_I2C, HID_GROUP_MULTITOUCH_WIN_8, VID_SYNAPTICS, PID_DLL0945_9310),
	HID_DEVICE(BUS_I2C, HID_GROUP_MULTITOUCH_WIN_8, VID_SYNAPTICS, PID_DLL0945_5406),
);

char _license[] SEC("license") = "GPL";
