:orphan:

.. _spacenavigator_case_study:

Case study: 3Dconnexion SpaceNavigator and the Gamepad API
==========================================================

This article illustrates how to diagnose and correct a "quirky" input
device on Linux. It will explore how input devices are handled
throughout the software stack from web browsers down to USB HID report
descriptors, highlighting the roles of udev, the kernel, and BPF. It
will also evaluate previous attempts to address the issue and propose
two fixes suitable for contributing upstream. This work resulted in the
merge request
`udev-hid-bpf MR!181 <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/merge_requests/181>`_.

The intent is to give readers a tour of the various open-source projects
composing the Linux input stack; to illustrate some of the tools,
techniques, and resources one can use when diagnosing the behavior of
input devices; and to provide an example of a situation in which
contributing to udev-hid-bpf is a reasonable course of action.

.. note:: This investigation was performed in February 2025. Links to
          code repositories are pinned to contemporary revisions.

.. contents:: Table of Contents

Introduction
------------

`3Dconnexion <http://3dconnexion.com/>`_ produces 3D input peripherals
commonly used in CAD, 3D modeling, geospatial analysis, and medical
diagnostics applications. The company provides a proprietary driver and
SDK for Windows and macOS, but their official Linux support is basically
useless. Fortunately, their USB devices follow the HID specifications
for multi-axis controllers and are fully supported by Linux's input
subsystem via the evdev interface. The
`spacenav <https://spacenav.sourceforge.net/>`_ project has implemented
open-source replacements for the 3Dconnexion driver daemon and SDK,
allowing the devices to be used in native applications like Blender.

But web-based applications are not able to communicate with the driver
daemon. While the spacenav project alludes to a proprietary websocket
protocol being used by some web apps, a simpler solution is to leverage
the W3C
`Gamepad API <https://developer.mozilla.org/en-US/docs/Web/API/Gamepad_API>`_.
On Windows, these controllers indeed show up as
6-axis "gamepads" in major browsers. But on Linux, my SpaceNavigator was
not recognized by either Firefox or Chrome. Let's walk through the
diagnosis and explore potential fixes.

The web browser
---------------

We'll start at the top of the stack and investigate how a web browser
(specifically, Firefox) decides which input devices to expose via the
gamepad API. Taking a look at
`LinuxGamepad.cpp <https://hg.mozilla.org/releases/mozilla-release/file/FIREFOX_RELEASE_128_END/dom/gamepad/linux/LinuxGamepad.cpp>`_,
we find the relevant-sounding function ``IsDeviceGamepad()``:

.. code:: cpp

   bool LinuxGamepadService::IsDeviceGamepad(struct udev_device* aDev) {
     if (!mUdev.udev_device_get_property_value(aDev, "ID_INPUT_JOYSTICK")) {
       return false;
     }
     // ...
   }

So we need our device to have the udev property ``ID_INPUT_JOYSTICK``
set to ``1``. We can query its properties using
``udevadm info -q property -n /dev/input/by-id/usb-3Dconnexion_SpaceNavigator-event-*``
to confirm that ``ID_INPUT_JOYSTICK`` is currently not set. Next stop:
udev.

The device manager
------------------

udev is a userspace daemon that responds to devices being plugged into
or unplugged from a Linux computer. It is configured with a large
selection of rules that can match against and modify device properties.
It would be straightforward to add a rule (under ``/etc/udev/rules.d``)
that matches the SpaceNavigator vendor and product IDs (obtained from,
e.g., ``lsusb``) and marks the device as a joystick:

::

   SUBSYSTEM=="input", ATTRS{idVendor}=="046D", ATTRS{idProduct}=="C626", ENV{ID_INPUT_JOYSTICK}="1"

If we do this, the SpaceNavigator will indeed show up in the Gamepad API
(after clicking one of its buttons---a prerequisite to compat browser
fingerprinting), but it will not report any of its axes. Furthermore,
other devices (like actual gamepads) don't need this kind of special
treatment in udev rules—they are marked as joysticks automatically. The
logic used to determine whether or not a device is a joystick isn't
obvious from udev's default rules and hardware database (under
``/usr/lib/udev/rules.d`` and ``/usr/lib/udev/hwdb.d``), and that's because it's
handled by the ``input_id`` builtin (invoked by ``60-input-id.rules``).
udev is maintained as part of the `systemd <https://systemd.io/>`_
project, and the logic we're looking for is in
`udev-builtin-input_id.c <https://github.com/systemd/systemd/blob/v255/src/udev/udev-builtin-input_id.c>`_:

.. code:: c

   if (num_joystick_buttons > 0 || num_joystick_axes > 0)
           is_joystick = true;

Reading the preceding code, a button is considered a "joystick button"
if its event code (defined in the kernel's
`linux/input-event-codes.h <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/input-event-codes.h?h=v6.12.13>`_)
is in certain ranges associated with triggers, d-pads, and other
joystick/gamepad functionality. Similarly, an axis is considered a
"joystick axis" if its event code represents absolute rotation or a
number of other input types associated with simulators and games. It's
important to clarify that these event categories are only used as a
heuristic for tagging a device with an appropriate default input type;
consumers like web browsers will still be able to act on events outside
of these ranges (for example, gamepads will often have translational
axes as well as rotational ones; it's just that udev does not consider
the presence of an absolute translational axis to be sufficient to
categorize a device as a "joystick").

So what events codes are produced by the SpaceNavigator? Running
``evemu-describe`` shows the following relevant events:

::

   #   Event type 1 (EV_KEY)
   #     Event code 256 (BTN_0)
   #     Event code 257 (BTN_1)
   #   Event type 2 (EV_REL)
   #     Event code 0 (REL_X)
   #     Event code 1 (REL_Y)
   #     Event code 2 (REL_Z)
   #     Event code 3 (REL_RX)
   #     Event code 4 (REL_RY)
   #     Event code 5 (REL_RZ)

So we see two buttons, but they have a generic type, rather than
anything joystick-specific (which is no surprise). We also see our 6
axes, including 3 rotational axes (RX, RY, and RZ), but they are marked
as "relative" rather than "absolute". This is why they don't satisfy the
joystick heuristic, and it's also why Firefox did not show any axes (but
did show buttons) even when we forced ``ID_INPUT_JOYSTICK`` to be ``1``.
Taking another look at Firefox's code, we see it only cares about
*absolute* axes.

But are these event types appropriate? Unlike a mouse, which can only
measure *changes* from its previous position ("relative" data), the
SpaceNavigator directly senses the tilt and displacement of its "knob".
It would make more sense for Linux to treat these as *absolute* axes.
So how were these event types determined?

The HID report descriptor
-------------------------

As a USB human interface device, the SpaceNavigator describes its
capabilities to its host computer using an `HID report
descriptor <https://docs.kernel.org/hid/hidintro.html>`_. In Linux, we
can see its contents via the device's ``report_descriptor`` file under
sysfs. (Note: this convenient file does not report the raw descriptor as
sent by the device, but we can compare it with, say, a Wireshark capture
to show that it has not been tampered with. Spoiler: we will be
tampering with it soon.) The raw report for my device, formatted as
hexadecimal bytes, looks like this::


   05 01 09 08 a1 01 a1 00 85 01 16 a2 fe 26 5e 01
   36 88 fa 46 78 05 55 0c 65 11 09 30 09 31 09 32
   75 10 95 03 81 06 c0 a1 00 85 02 09 33 09 34 09
   35 75 10 95 03 81 06 c0 a1 02 85 03 05 01 05 09
   19 01 29 02 15 00 25 01 35 00 45 01 75 01 95 02
   81 02 95 0e 81 03 c0 a1 02 85 04 05 08 09 4b 15
   00 25 01 95 01 75 01 91 02 95 01 75 07 91 03 c0
   06 00 ff 09 01 a1 02 15 80 25 7f 75 08 09 3a a1
   02 85 05 09 20 95 01 b1 02 c0 a1 02 85 06 09 21
   95 01 b1 02 c0 a1 02 85 07 09 22 95 01 b1 02 c0
   a1 02 85 08 09 23 95 07 b1 02 c0 a1 02 85 09 09
   24 95 07 b1 02 c0 a1 02 85 0a 09 25 95 07 b1 02
   c0 a1 02 85 0b 09 26 95 01 b1 02 c0 a1 02 85 13
   09 2e 95 01 b1 02 c0 a1 02 85 19 09 31 95 04 b1
   02 c0 c0 c0

Parsing the report with, e.g.,
`hid-recorder <https://github.com/hidutils/hid-recorder>`_,
reveals these contents:

::

   0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
   0x09, 0x08,        // Usage (Multi-axis Controller)
   0xA1, 0x01,        // Collection (Application)
   0xA1, 0x00,        //   Collection (Physical)
   0x85, 0x01,        //     Report ID (1)
   0x16, 0xA2, 0xFE,  //     Logical Minimum (-350)
   0x26, 0x5E, 0x01,  //     Logical Maximum (350)
   0x36, 0x88, 0xFA,  //     Physical Minimum (-1400)
   0x46, 0x78, 0x05,  //     Physical Maximum (1400)
   0x55, 0x0C,        //     Unit Exponent (-4)
   0x65, 0x11,        //     Unit (System: SI Linear, Length: Centimeter)
   0x09, 0x30,        //     Usage (X)
   0x09, 0x31,        //     Usage (Y)
   0x09, 0x32,        //     Usage (Z)
   0x75, 0x10,        //     Report Size (16)
   0x95, 0x03,        //     Report Count (3)
   0x81, 0x06,        //     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
   0xC0,              //   End Collection
   0xA1, 0x00,        //   Collection (Physical)
   0x85, 0x02,        //     Report ID (2)
   0x09, 0x33,        //     Usage (Rx)
   0x09, 0x34,        //     Usage (Ry)
   0x09, 0x35,        //     Usage (Rz)
   0x75, 0x10,        //     Report Size (16)
   0x95, 0x03,        //     Report Count (3)
   0x81, 0x06,        //     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
   0xC0,              //   End Collection

   // ...

   0xC0,              // End Collection

   // 228 bytes

The relevant data is at offsets 36-37 (for the X, Y, and Z axes) and
53-54 (for the Rx, Ry, and Rz axes). The bytes ``0x81 0x06`` indicate a
relative input item, whereas we would expect ``0x81 0x02`` for an
absolute one (see `Device class definition for
HID <https://www.usb.org/sites/default/files/hid1_11.pdf>`_, page 30).
So the device is indeed reporting that its axes are relative rather than
absolute. This is arguably a firmware bug. (Note: a `Stack Overflow
post <https://stackoverflow.com/questions/70134247/spacemouse-compact-not-working-with-js-gamepad-api-in-chrome-on-ubuntu>`_
claims that the report descriptor has been fixed in newer products such
as the SpaceMouse Wireless.)

It's certainly not the first device to have errors in its HID report
descriptor, though. Linux drivers are full of code to work around
similar device "quirks." In fact, Linux already attempts to address this
very issue!

The broken fix and a workaround
-------------------------------

Linux 2.6.33 (released February 2010) contains commit
`24985cf68612 <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24985cf68612a5617d396b0b188cec807641cde1>`_:

	.. code-block:: text

	   HID: support Logitech/3DConnexion SpaceTraveler and SpaceNavigator
	   These devices wrongly report their axes as relative instead of absolute.
	   
	   Fix this in up report descriptor of the device before it enters the parser.

With that change, the Linux HID driver for Logitech devices recognizes
the SpaceNavigator product ID (``0xC626``) and overwrites the first two
``0x81 0x06`` input items with ``0x81 0x02``, as desired. Unfortunately,
it does so at offsets of 32 and 49, which are 4 bytes before they occur
in our unit's report descriptor. Perhaps 3Dconnexion revised the
firmware in a subsequent production run (my SpaceNavigator was purchased
in 2016, and there is `some
evidence <https://www.jciger.com/archives/74>`_ that that the fix
worked for others around 2010—see comments in
`spacenavig.c <https://www.jciger.com/files/software/linux/spacenav/spacenavig.c>`_).
Regardless, this fix is ineffective for my device, and I'm not the
only one affected.

The `relabsd <https://github.com/nsensfel/relabsd>`_ project exists
specifically to translate relative axes into absolute ones in order to
use more devices as gamepads (they mention the SpaceNavigator as a
candidate device, and SDL as a potential consumer). This project
consists of a userspace daemon that reads events via evdev, translates
them as necessary, and then injects them into a new virtual device.
While their approach is flexible and effective, such runtime translation
would not be necessary (at least for the SpaceNavigator) if the kernel
fix were working as intended.

Patching the kernel to apply the fix to my variant of the SpaceNavigator
should be straightforward and hopefully unobjectionable (the process for
contributing such a patch upstream is currently beyond the scope of this
article). A quick fix in
`hid-lg.c <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/hid/hid-lg.c?h=v6.12#n442>`_
to handle both device variants could look something like this:

.. code:: c

   if (drv_data->quirks & LG_RDESC_REL_ABS) {
       if (*rsize >= 51 &&
               rdesc[32] == 0x81 && rdesc[33] == 0x06 &&
               rdesc[49] == 0x81 && rdesc[50] == 0x06) {
           hid_info(hdev,
                "fixing up rel/abs in Logitech report descriptor\n");
           rdesc[33] = rdesc[50] = 0x02;
       } else if (*rsize >= 55 &&
               rdesc[36] == 0x81 && rdesc[37] == 0x06 &&
               rdesc[53] == 0x81 && rdesc[54] == 0x06) {
           hid_info(hdev,
                "fixing up rel/abs in Logitech report descriptor\n");
           rdesc[37] = rdesc[54] = 0x02;
       }
   }

(A more robust fix would parse the descriptor in order to find the input
items associated with the axes of interest, but that doesn't seem to be
the norm for fixups like this.) However, it will be a long time before
such a fix is deployed broadly in professional work environments, which
tend to run older kernels for many years. It would be nice if there
were a way to apply such fixes without recompiling one's kernel.

Fixing with a packet filter
---------------------------

It is possible to extend much of the Linux kernel's functionality at
runtime using eBPF, and the input subsystem is no exception.
`HID-BPF <https://docs.kernel.org/hid/hid-bpf.html>`_ provides a way to
fix report descriptors using eBPF, and the
`udev-hid-bpf <https://libevdev.pages.freedesktop.org/udev-hid-bpf/index.html>`_
project provides a framework for running such eBPF programs from udev
rules.

Browsing the project's existing BPF programs, applying device fixups is
done very similarly to how they are applied in the kernel itself. Two
differences are worth highlighting: first, the length of the report
descriptor is typically checked against the expected value(s), and
second, the descriptor is examined up front to determine whether the
kernel has already applied the fix. This is especially courteous given
how udev-hid-bpf works: the BPF program is loaded based on udev rules,
and, before its fixup can be executed, the device is virtually
disconnected and reconnected by the kernel. Avoiding redundant fixes
thus also avoids unnecessary virtual disconnects.

Unfortunately, while I know the descriptor size for my device, I do not
not know the size for the devices that are currently being successfully
fixed up by the kernel. Determining this would improve the robustness of
the BPF fix.

Surveying other people's hardware
---------------------------------

It would be great if we had a record of the HID report descriptor that
was used to develop the original kernel fix back in 2009. But I had no
luck finding such a record with Internet searches. What I did find,
however, was a database of hardware details published by Linux users:
`linux-hardware.org <https://linux-hardware.org/>`_.

Searching for computers with a SpaceNavigator attached returns 54
results. Data includes logs from ``lsusb``, which will tell us the
report descriptor's length, but unfortunately they do not include the
report descriptor's data (it is displayed as ``** UNAVAILABLE **`` if
the device is currently "bound"). Interestingly, at least three variants
of the SpaceNavigator are represented in the database:

.. list-table:: Frequency of device variants
   :header-rows: 1

   * - Report descriptor length
     - Instances
   * - 202
     - 21
   * - 217
     - 26
   * - 228
     - 7 (plus me)

Presumably at least one of those variants uses the offsets reflected in
the original kernel fix, but it is unknown which offsets are used by
the other variant. Without more information, and to avoid regressing the
current fix, our program will try either set of offsets for devices
with any of these three descriptor lengths.

Conclusion
----------

This is enough information to open an
`issue <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/issues/53>`_
in the udev-hid-bpf GitLab project and propose an improved fixup in a
`merge request <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/merge_requests/181>`_.
Since the project attempts to submit fixes for legitimate "quirks" to
the Linux kernel, it is important to adhere to Linux standards when
formatting code and commit messages; the command
``/path/to/linux/scripts/checkpatch.pl -g HEAD`` will flag most such
issues.

As always, test your work as broadly as you can, and be sure to test
every revision made during the code review process. A unique challenge
may come from the BPF verifier, which can sometimes complain about
compiler optimizations beyond your control. Unfortunately,
``udev-hid-bpf`` does not report detailed verifier errors, so you may
need to use a command like ``bpftool prog load`` to see them.

In the end, in this case, simply applying the relative-to-absolute
fix at the appropriate two offsets for my device variant was
sufficient to make the SpaceNavigator usable via the Gamepad API in both
Firefix and Chrome. But were we not that lucky, knowledge of udev,
evdev (or libinput in other situations), and web browser internals,
combined with the ability to rapidly iterate on kernel logic using BPF,
would help us identify and address any remaining gaps in the chain.
