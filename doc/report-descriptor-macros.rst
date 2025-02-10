.. _report_descriptor_macros:

HID Report Descriptor Macros
============================

In the tutorial's :ref:`tutorial_rdesc_fixup` section the example code changed
individual bytes in the report descriptor. In many cases, particular where a
new device needs to be supported, a more readable approach is to replace the
report descriptor wholesale. For this, ``udev-hid-bpf`` provides a series of
helper macros, see the `hid_report_helpers.h <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/blob/main/src/bpf/hid_report_helpers.h>`_.
source file.

These macros are styled in the output format of `hid-recorder <https://github.com/hidutils/hid-recorder>`_.

Below is an annotated extract of an example report descriptor:

.. code-block:: c

  static const __u8 fixed_rdesc_vendor[] = {
          UsagePage_Digitizers                 // <- set usage page to Digitizer
          Usage_Dig_Digitizer                  // <- set usage ID to Digitizer (page: Digitizer)
          CollectionApplication(               // <- Start an Application Collection
                  // -- Byte 0 in report
                  ReportId(0x15)
                  Usage_Dig_Stylus             // <- set usage ID to Stylus (page: Digitizer)
                  CollectionPhysical(
                          // -- Byte 1 in report
                          LogicalMinimum_i8(0)
                          LogicalMaximum_i8(1)
                          ReportSize(1)
                          Usage_Dig_TipSwitch
                          Usage_Dig_BarrelSwitch
                          Usage_Dig_SecondaryBarrelSwitch
                          ReportCount(3)
                          Input(Var|Abs)       // <- Input field, abs values
                          ReportCount(3)
                          Input(Const)         // <- Input field, const (i.e. padding)
                          // ... many more fields omitted ...
                  )
                  FixedSizeVendorReport(11)    // <- see "Enforcing the right HID Report size"
          )                                    // <- closes the Application Collection
  };

This report descriptor can then be used to wholesale replace the device's report descriptor:

.. code-block:: c

  SEC(HID_BPF_RDESC_FIXUP)
  int BPF_PROG(my_rdesc_fixup, struct hid_bpf_ctx *hctx)
  {
        __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, HID_MAX_DESCRIPTOR_SIZE /* size */);

        if (!data)
                return 0; /* EPERM check */

        __builtin_memcpy(data, fixed_rdesc_vendor, sizeof(fixed_rdesc_vendor));
        return sizeof(fixed_rdesc_vendor);
  }

This approach is particularly useful where the device sends all events in a HID Vendor Collection
that would otherwise be ignored by the kernel. By overwriting the HID report descriptor
with one that identifies the various components of the HID report it may be possible
to make the device work without having to change the actual HID reports in the BPF program.

Enforcing the right HID Report size
-----------------------------------

However there is a drawback: the kernel discards any any HID reports that are
larger than the largest report in the HID report descriptor. Thus a modified
HID Report Descriptor must include **at least one HID Report** that is (at
least) the same size as the **largest** report in the original HID Report
Descriptor.

In other words, if the original HID Report Descriptor describes three
reports of sizes 8, 16 and 20 the fixed HID Report Descriptor **must** include
at least one report that is of size 20.

This can easily be achieved with the ``FixedSizeVendorReport(len)`` helper macro as shown above.
This macro will add one additional vendor-specific HID Report to the HID Report Descriptor with
the given size in bytes. This HID Report will be ignored by the kernel but
guarantees HID reports are not immediately discarded before the BPF program gets to look at them.
The ``FixedSizeVendorReport(len)`` macro must not be used more than once per
report descriptor and should not be larger than necessary
to avoid unnecessary buffer allocations in the kernel.
