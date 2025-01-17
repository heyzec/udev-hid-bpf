#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 Red Hat

from . import Bpf, HidProbeArgs

import logging
import struct
import pytest

logger = logging.getLogger(__name__)


@pytest.fixture
def bpf(source: str):
    """
    A fixture that allows parametrizing over a number of sources. Use with e.g.::

        @pytest.mark.parametrize("source", ["0010-FR-TEC__Raptor-Mach-2"])
        def test_something(bpf):
            pass
    """
    assert source is not None
    bpf = Bpf.load(source)
    assert bpf is not None
    yield bpf


@pytest.mark.parametrize("source", ["0010-FR-TEC__Raptor-Mach-2"])
class TestFrTecRaptorMach2:
    def test_probe(self, bpf):
        probe_args = HidProbeArgs(rdesc_size=232)
        probe_args.rdesc[177] = 0xEF
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

        probe_args.rdesc[177] = 0x12  # random value
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

    def test_rdesc(self, bpf):
        rdesc = bytes(4096)

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        assert data[177] == 0x07


@pytest.mark.parametrize("source", ["0010-mouse_invert_y"])
class TestUserhacksInvertY:
    def test_probe(self, bpf):
        probe_args = HidProbeArgs()
        probe_args.rdesc_size = 123
        pa = bpf.probe(probe_args)
        assert pa.retval == -22

        probe_args.rdesc_size = 71
        pa = bpf.probe(probe_args)
        assert pa.retval == 0

    @pytest.mark.parametrize("y", [1, -1, 10, -256])
    def test_event(self, bpf, y):
        # this device has reports of size 9
        values = (0, 0, 0, y, 0, 0, 0, 0, 0)
        report = struct.pack("<3bh5b", *values)

        values = bpf.hid_bpf_device_event(report=report)
        values = struct.unpack("<3bh5b", values)
        y_out = values[3]
        assert y_out == -y


@pytest.mark.parametrize("source", ["0010-Rapoo__M50-Plus-Silent"])
class TestRapooM50Plus:
    def test_rdesc_fixup(self, bpf):
        rdesc = bytearray(4096)
        rdesc[17] = 0x03

        data = bpf.hid_bpf_rdesc_fixup(rdesc=rdesc)
        rdesc[17] = 0x05
        assert data == rdesc


@pytest.mark.parametrize("source", ["0010-XPPen__DecoMini4"])
class TestXPPenDecoMini4:
    @pytest.mark.parametrize(
        "report,expected",
        [
            # Invalid report descriptor
            ("02 01 02 03 04 05 06 07", "02 01 02 03 04 05 06 07"),
            # Button 1
            ("06 00 05 00 00 00 00 00", "06 01 00 00 00 00 00 00"),
            # Button 2
            ("06 00 08 00 00 00 00 00", "06 02 00 00 00 00 00 00"),
            # Button 3
            ("06 04 00 00 00 00 00 00", "06 04 00 00 00 00 00 00"),
            # Button 4
            ("06 00 2c 00 00 00 00 00", "06 08 00 00 00 00 00 00"),
            # Button 5
            ("06 01 16 00 00 00 00 00", "06 10 00 00 00 00 00 00"),
            # Button 6
            ("06 01 1d 00 00 00 00 00", "06 20 00 00 00 00 00 00"),
            # Buttons 3 and 5
            ("06 05 16 00 00 00 00 00", "06 14 00 00 00 00 00 00"),
            # All buttons
            ("06 05 05 08 2c 16 1d 00", "06 3f 00 00 00 00 00 00"),
        ],
    )
    def test_button_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected


@pytest.mark.parametrize("source", ["0010-TUXEDO__Sirius-16-Gen1-and-Gen2"])
class TestTUXEDOSirius16Gen1andGen2:
    @pytest.mark.parametrize(
        "report,expected",
        [
            pytest.param(
                "01 00 00 68 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                id="single-f13-key-press",
            ),
            pytest.param(
                "01 00 00 04 05 06 07 08 09 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "01 00 00 04 05 06 07 08 09 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                id="six-keys-and-then-f13-key-down",
            ),
            pytest.param(
                "01 00 00 68 68 68 68 68 68 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
                "01 00 00 00 00 00 00 00 00 ff ff ff ff ff ff ff ff ff ff ff ff ff fe ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
                id="edge-case-all-bits-set",
            ),
        ],
    )
    def test_button_events(self, bpf, report, expected):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected


@pytest.mark.parametrize("source", ["0010-XPPen__ACK05"])
class TestXPPenACK05:
    @pytest.mark.parametrize(
        "report,expected",
        [
            # anything but report ID 02 should be forwarded as such
            pytest.param(
                "04 f0 01 00 00 00 00 00 00 00 00 00",
                "04 f0 01 00 00 00 00 00 00 00 00 00",
                id="untouched-report",
            ),
            # button events are on report ID f0 with a size of 8, mostly untouched
            pytest.param(
                "02 f0 01 00 00 00 00 00 00 00 00 00",
                "f0 f0 01 00 00 00 00 00",
                id="single-button1-press",
            ),
            # CCW wheel events are button events with 0x02 changed to 0xff
            pytest.param(
                "02 f0 00 00 00 00 00 02 00 00 00 00",
                "f0 f0 00 00 00 00 00 ff",
                id="ccw-wheel",
            ),
            # battery reports are on f2 and of size 5
            pytest.param(
                "02 f2 01 00 00 00 00 00 00 00 00 00",
                "f2 f2 01 00 00",
                id="battery-report",
            ),
        ],
    )
    def test_button_events(self, bpf, report: str, expected: str):
        event = bpf.hid_bpf_device_event(report=report)
        assert event == expected
