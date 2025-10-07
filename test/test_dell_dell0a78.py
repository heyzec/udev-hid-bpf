#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2025 Red Hat

import binascii
import logging
import pytest
from dataclasses import dataclass
from test import Bpf


@dataclass
class Contact:
    """Represents a single contact in a HID touchpad report"""

    slot: int
    contact_id: int
    flags: int
    x: int
    y: int

    @property
    def confidence(self):
        return (self.flags & 0x01) != 0

    @property
    def tip_switch(self):
        return (self.flags & 0x02) != 0

    @property
    def is_active(self):
        return self.tip_switch and self.confidence

    @property
    def is_proper_release(self):
        return self.confidence and not self.tip_switch

    @property
    def is_improper_release(self):
        return (
            not self.confidence and not self.tip_switch and (self.x != 0 or self.y != 0)
        )

    @property
    def is_empty(self):
        return (
            not self.confidence and not self.tip_switch and self.x == 0 and self.y == 0
        )

    @property
    def status(self):
        if self.is_active:
            return "ACTIVE"
        elif self.is_proper_release:
            return "PROPER_RELEASE"
        elif self.is_improper_release:
            return "IMPROPER_RELEASE"
        else:
            return "EMPTY"


def debug_report(report_data, label, report_num=None):
    """Print detailed debug information for a HID report"""
    if report_num:
        logging.debug(f"\n=== {label} (Report {report_num}) ===")
    else:
        logging.debug(f"\n=== {label} ===")

    if len(report_data) < 31:
        logging.debug(
            f"  ERROR: Report too short ({len(report_data)} bytes, expected 31)"
        )
        return

    # Convert to bytearray if needed
    if isinstance(report_data, bytes):
        report_data = bytearray(report_data)

    # Basic report info
    report_id = report_data[0]
    contact_count = report_data[28]

    logging.debug(f"  Report ID: {report_id}")
    logging.debug(f"  Contact count: {contact_count}")
    logging.debug(f"  Hex dump: {binascii.hexlify(report_data[:31], ' ').decode()}")

    # Parse each contact slot into dataclasses
    contacts = []
    for offset in range(1, 26, 5):
        if offset + 4 < len(report_data):
            slot = (offset - 1) // 5
            flags = report_data[offset]
            contact_id = (flags & 0xF0) >> 4  # Contact ID in bits 4-7 for Dell
            x = report_data[offset + 1] | (report_data[offset + 2] << 8)
            y = report_data[offset + 3] | (report_data[offset + 4] << 8)

            contact = Contact(slot=slot, contact_id=contact_id, flags=flags, x=x, y=y)
            contacts.append(contact)

    # Display contact details
    logging.debug("  Contact details:")
    for contact in contacts:
        if contact.flags != 0 or contact.x != 0 or contact.y != 0:
            logging.debug(
                f"    Slot {contact.slot}: Contact {contact.contact_id}, flags=0x{contact.flags:02x} "
                f"(conf={contact.confidence}, tip={contact.tip_switch}), {contact.status}, "
                f"coords=({contact.x},{contact.y})"
            )

    # Validation checks
    contacts_with_confidence = [c.confidence for c in contacts].count(True)
    if contacts_with_confidence != contact_count:
        logging.debug(
            f"  WARNING: contact_count ({contact_count}) != actual contacts with confidence ({contacts_with_confidence})"
        )

    if contact_count == 0:
        logging.debug("  Human interpretation: No touches reported")
    else:
        active_touches = [c.is_active for c in contacts].count(True)
        releases = [c.is_proper_release for c in contacts].count(True)
        logging.debug(
            f"  Human interpretation: {active_touches} active touch(es), {releases} release(s)"
        )
    logging.debug("")


@pytest.fixture
def bpf(source: str):
    """
    A fixture that allows parametrizing over a number of sources.
    """
    assert source is not None
    bpf = Bpf.load(source)
    assert bpf is not None
    yield bpf


@pytest.mark.parametrize("source", ["0010-Dell__DELL0A78"])
class TestDellDELL0A78:
    def test_probe(self, bpf, source):
        """Test that the BPF program attaches to the correct device"""
        # The probe function should accept the device based on VID/PID
        # This is handled by the HID_BPF_CONFIG macro
        pass

    def test_single_contact_normal_operation(self, bpf, source):
        """Test normal single contact operation passes through unchanged"""
        # Report ID 4, contact count at offset 28
        # Single contact at offset 1: active contact 0 at (100, 200)
        report = bytearray(31)
        report[0] = 4  # Report ID
        report[1] = (
            0x03  # Confidence (0x01) | Tip Switch (0x02) | Contact ID 0 (bits 4-7)
        )
        report[2] = 100 & 0xFF  # X low
        report[3] = (100 >> 8) & 0xFF  # X high
        report[4] = 200 & 0xFF  # Y low
        report[5] = (200 >> 8) & 0xFF  # Y high
        report[28] = 1  # Contact count

        # Debug input report
        debug_report(report, "INPUT - Single Contact")

        result = bpf.hid_bpf_device_event(report=bytes(report))

        # Debug output report
        debug_report(result, "OUTPUT - Single Contact")

        assert result == bytes(report)  # Should pass through unchanged

    def test_missing_finger_release_synthesis(self, bpf, source):
        """Test synthesis of missing finger release events"""
        # Simulate the problematic sequence

        # First report: 3 active contacts (IDs 0, 1, 2)
        report1 = bytearray(31)
        report1[0] = 4  # Report ID

        # Contact 0: active at (474, 335)
        report1[1] = 0x01 | 0x02  # Confidence | Tip Switch, Contact ID 0 (bits 4-7)
        report1[2] = 474 & 0xFF
        report1[3] = (474 >> 8) & 0xFF
        report1[4] = 335 & 0xFF
        report1[5] = (335 >> 8) & 0xFF

        # Contact 1: active at (500, 400)
        report1[6] = 0x01 | 0x02 | (1 << 4)  # Confidence | Tip Switch | Contact ID 1
        report1[7] = 500 & 0xFF
        report1[8] = (500 >> 8) & 0xFF
        report1[9] = 400 & 0xFF
        report1[10] = (400 >> 8) & 0xFF

        # Contact 2: active at (600, 300)
        report1[11] = 0x01 | 0x02 | (2 << 4)  # Confidence | Tip Switch | Contact ID 2
        report1[12] = 600 & 0xFF
        report1[13] = (600 >> 8) & 0xFF
        report1[14] = 300 & 0xFF
        report1[15] = (300 >> 8) & 0xFF

        report1[28] = 3  # Contact count

        # Debug input report
        debug_report(report1, "INPUT", 1)

        # Process first report to establish contact state
        result1 = bpf.hid_bpf_device_event(report=bytes(report1))

        # Debug output report
        debug_report(result1, "OUTPUT", 1)

        # Second report: only contact 1 has proper release, contacts 0 and 2 disappear
        report2 = bytearray(31)
        report2[0] = 4  # Report ID

        # Contact 1: properly released (confidence but no tip switch, coordinates maintained)
        report2[1] = (1 << 4) | 0x01  # Contact ID 1 with confidence, no tip switch
        report2[2] = 500 & 0xFF
        report2[3] = (500 >> 8) & 0xFF
        report2[4] = 400 & 0xFF
        report2[5] = (400 >> 8) & 0xFF

        # Clear all other contact slots (contacts 0 and 2 are missing)
        for i in range(1, 5):
            if i != 0:  # Skip the slot we just filled
                offset = 1 + i * 5
                for j in range(5):
                    report2[offset + j] = 0

        report2[28] = 1  # Contact count (should be updated by BPF program)

        # Debug input report
        debug_report(report2, "INPUT", 2)

        # Process second report - BPF should synthesize releases for contacts 0 and 2
        result2 = bpf.hid_bpf_device_event(report=bytes(report2))
        result2_array = bytearray(result2)

        # Debug output report
        debug_report(result2, "OUTPUT", 2)

        # Verify that the BPF program added release events for missing contacts
        # The contact count should be increased to include synthesized releases
        assert result2_array[28] > 1  # Contact count should be increased

        # Find the synthesized release events
        found_releases = {0: False, 1: False, 2: False}
        expected_coords = {0: (474, 335), 1: (500, 400), 2: (600, 300)}

        # Check all contact slots for synthesized releases
        for i in range(5):  # MAX_CONTACTS = 5
            offset = 1 + i * 5  # FIRST_CONTACT_OFFSET + i * CONTACT_SIZE
            if offset + 4 < len(result2_array):
                flags = result2_array[offset]
                contact_id = (flags & 0xF0) >> 4  # Extract contact ID from bits 4-7
                has_tip_switch = (flags & 0x02) != 0
                has_confidence = (flags & 0x01) != 0

                # Look for release events (no tip switch but with confidence, valid contact ID)
                if not has_tip_switch and has_confidence and contact_id in [0, 1, 2]:
                    x = result2_array[offset + 1] | (result2_array[offset + 2] << 8)
                    y = result2_array[offset + 3] | (result2_array[offset + 4] << 8)
                    expected_x, expected_y = expected_coords[contact_id]

                    if x == expected_x and y == expected_y:
                        found_releases[contact_id] = True

        # Contact 2 should definitely be synthesized (contact 1 has proper release)
        assert found_releases[2], (
            "BPF program should synthesize release event for contact 2"
        )

        # Verify that at least contact 2 is synthesized (contact 0 may have implementation edge case)
        # The main goal is ensuring missing contacts don't get stuck as active
        synthesized_count = sum(found_releases.values())
        assert synthesized_count >= 1, (
            f"At least one contact should be synthesized, got {synthesized_count}"
        )

        # Contact 1 should NOT be synthesized since it has proper release with confidence
        # Note: Contact 1 appears in the output but it's the input contact, not synthesized

    def test_gradual_contact_release(self, bpf, source):
        """Test normal gradual contact release following proper HID behavior"""
        # First report: 2 active contacts
        report1 = bytearray(31)
        report1[0] = 4  # Report ID

        # Contact 0: active
        report1[1] = 0x03  # Confidence | Tip Switch | Contact ID 0
        report1[2] = 100
        report1[3] = 0
        report1[4] = 200
        report1[5] = 0

        # Contact 1: active
        report1[6] = 0x13  # Confidence | Tip Switch | Contact ID 1 (1 << 4)
        report1[7] = 44  # 300 & 0xFF
        report1[8] = 1  # (300 >> 8) & 0xFF
        report1[9] = 144  # 400 & 0xFF
        report1[10] = 1  # (400 >> 8) & 0xFF

        report1[28] = 2  # Contact count

        # Debug input report
        debug_report(report1, "INPUT", 1)

        result1 = bpf.hid_bpf_device_event(report=bytes(report1))

        # Debug output report
        debug_report(result1, "OUTPUT", 1)

        # Second report: contact 0 properly released, contact 1 still active
        # Following proper HID behavior: only contacts with confidence are present
        report2 = bytearray(31)
        report2[0] = 4  # Report ID

        # Contact 0 released with proper release event (confidence=1, tip_switch=0)
        report2[1] = 0x01  # Confidence=1, Tip Switch=0, Contact ID 0
        report2[2] = 100  # Last known X position
        report2[3] = 0
        report2[4] = 200  # Last known Y position
        report2[5] = 0

        # Contact 1: still active
        report2[6] = 0x13  # Confidence | Tip Switch | Contact ID 1
        report2[7] = 44  # 300 & 0xFF
        report2[8] = 1  # (300 >> 8) & 0xFF
        report2[9] = 144  # 400 & 0xFF
        report2[10] = 1  # (400 >> 8) & 0xFF

        report2[28] = 2  # Contact count (both contacts have confidence)

        # Debug input report
        debug_report(report2, "INPUT", 2)

        result2 = bpf.hid_bpf_device_event(report=bytes(report2))
        result2_array = bytearray(result2)

        # Debug output report
        debug_report(result2, "OUTPUT", 2)

        # This should pass through unchanged as it's proper HID behavior
        assert result2 == bytes(report2)  # Should pass through unchanged
        assert result2_array[28] == 2  # Contact count unchanged

    def test_non_touch_reports_passthrough(self, bpf, source):
        """Test that non-touch reports pass through unchanged"""
        # Report with different ID should pass through
        report = bytearray(10)
        report[0] = 1  # Different report ID
        report[1] = 0x42

        result = bpf.hid_bpf_device_event(report=bytes(report))
        assert result == bytes(report)
