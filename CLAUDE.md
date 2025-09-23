# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System and Development Commands

This project uses Meson build system that wraps Rust's cargo for the main application and compiles BPF programs.

### Build Commands
```bash
# Initial setup
meson setup builddir/

# Compile the project
meson compile -C builddir/

# Install (requires sudo for udev rules and hwdb files)
meson install -C builddir

# Run tests
meson test -C builddir
```

### BPF coding style
The BPF (especially in `src/bpf/testing/`) eventually land in the kernel tree,
therefore they should be using the same coding style than the kernel:
- tabs are 8 characters long
- no spaces before tabs
- no space between the function name and the parenthesis
- `const char *variable` instead of `const char* variable`
- maximum line size of 100 chars, preferrably under 80 chars
- spaces between operators and left/right arguments
- a blank line must be inserted after declarations
- braces {} are not necessary for single statement blocks
- an empty line must be at the end of the file
- line returns are of linux type, not windows

### BPF Program Categories
The project organizes BPF programs into three categories:
- `src/bpf/testing/` - New quirks under development, enabled by default
- `src/bpf/stable/` - Proven quirks accepted upstream, for distribution packaging
- `src/bpf/userhacks/` - User-specific modifications that won't be upstreamed

Control which categories to build:
```bash
meson configure -Dbpfs=testing,stable builddir/
```

Filter specific BPF files:
```bash
meson configure -Dfilter-bpf=Foo,Bar builddir/
```

### BPF files naming scheme

See @doc/filename-conventions.rst

### Testing Single BPF Files
```bash
# Build and install a single BPF file (auto-enables all categories)
sudo udev-hid-bpf --verbose add /sys/bus/hid/devices/0003:11C0:5606.* - ./builddir/src/bpf/my_awesome_hid_bpf_filter.bpf.c
```

## Architecture Overview

### Core Components

**Rust Application (`src/main.rs`)**
- Main entry point that handles CLI commands: `add`, `remove`, `list-devices`, `list-bpf-programs`, `inspect`, `install`
- Uses libbpf-rs for BPF program loading and management
- Integrates with udev for automatic device detection and BPF program attachment

**BPF Programs (`src/bpf/`)**
- Written in C, compiled to BPF bytecode using clang or bpf-gcc
- Each program targets specific devices via HID_DEVICE() macros in BTF metadata
- Programs hook into HID subsystem to fix hardware/firmware issues or implement user preferences

**Build Integration (`build.rs`, `src/bpf/meson.build`)**
- Custom build system that compiles BPF programs during Rust build
- Generates vmlinux.h for BPF compilation (either provided or auto-generated)
- Creates numbered BPF object files with priority-based loading

### Key Modules

**HID-BPF Integration (`src/hidudev.rs`)**
- Handles device discovery via udev
- Manages BPF program loading and attachment to HID devices
- Searches for matching BPF programs based on device modalias

**Modalias Processing (`src/modalias.rs`)**
- Extracts device identification from BTF metadata in BPF programs
- Matches devices to appropriate BPF programs based on bus, vendor ID, product ID

**BPF Management (`src/bpf.rs`)**
- Low-level BPF program loading and attachment
- Handles BPF object lifecycle management

### Device Categories and Quirks vs User Hacks

**Quirks** (testing/stable): Fix objective hardware/firmware bugs
- Inverted axes, wrong value ranges, impossible event sequences
- Eventually upstreamed to kernel
- Examples: tablet button mappings, mouse movement corrections

**User Hacks** (userhacks): Subjective user preferences
- Button swapping, axis muting for specific applications
- Never upstreamed, maintained as examples
- Examples: mouse button remapping, disable specific HID events

### Testing Framework

The project includes a Python-based testing framework (`test/`) that:
- Loads BPF programs for unit testing
- Simulates HID device events and report descriptors
- Validates BPF program behavior without requiring physical devices
- Uses pytest with parametrized test cases for multiple device variants

### Installation and Deployment

The tool integrates with the system through:
- udev rules (81-hid-bpf.rules) for automatic program loading
- hwdb files for device property matching
- Firmware directory installation (/lib/firmware/hid/bpf/)

### Important Development Notes

- BPF programs must include HID_DEVICE() entries in BTF metadata for automatic loading
- The numbering scheme (0010-, 0020-, etc.) determines loading priority
- Programs with lower IDs load first, struct_ops programs have priority over tracing
- Each BPF program should target specific device bus:vendor:product combinations
- Testing programs should eventually move to stable/ once proven and upstreamed

## Helpful information

### HID recorder files

The devices are often represented by a hid-recorder output file. hid-recorder is a tool that captures hidraw description and events to replay them through the uhid kernel module for debugging kernel issues with HID input devices.

This file contains several structured parts with specific syntax:
- Device identification information (D:, N:, P:, I: lines)
- Report descriptor (R: line)
- HID events (E: lines)
- Comments (# lines)

#### hid-recorder report descriptor

The HID report descriptor follows the HID standard and is provided in all files
in the following form:

```
R: 665 05 01 09 02 a1 01 85 02 09 01 a1 00 05 09 19 01 29 02 15 00 25 01 75 01 95 02 81 02 95 06 81 01 05 01 09 30 09 31 15 81 25 7f 75 08 95 02 81 06 c0 c0 05 0d 09 05 a1 01 85 03 05 0d 09 22 a1 02 15 00 25 01 09 47 09 42 95 02 75 01 81 02 95 01 75 03 25 05 09 51 81 02 75 01 95 03 81 03 05 01 15 00 26 45 05 75 10 55 0e 65 11 09 30 35 00 46 64 04 95 01 81 02 46 a2 02 26 29 03 09 31 81 02 c0 05 0d 09 22 a1 02 15 00 25 01 09 47 09 42 95 02 75 01 81 02 95 01 75 03 25 05 09 51 81 02 75 01 95 03 81 03 05 01 15 00 26 45 05 75 10 55 0e 65 11 09 30 35 00 46 64 04 95 01 81 02 46 a2 02 26 29 03 09 31 81 02 c0 05 0d 09 22 a1 02 15 00 25 01 09 47 09 42 95 02 75 01 81 02 95 01 75 03 25 05 09 51 81 02 75 01 95 03 81 03 05 01 15 00 26 45 05 75 10 55 0e 65 11 09 30 35 00 46 64 04 95 01 81 02 46 a2 02 26 29 03 09 31 81 02 c0 05 0d 09 22 a1 02 15 00 25 01 09 47 09 42 95 02 75 01 81 02 95 01 75 03 25 05 09 51 81 02 75 01 95 03 81 03 05 01 15 00 26 45 05 75 10 55 0e 65 11 09 30 35 00 46 64 04 95 01 81 02 46 a2 02 26 29 03 09 31 81 02 c0 05 0d 09 22 a1 02 15 00 25 01 09 47 09 42 95 02 75 01 81 02 95 01 75 03 25 05 09 51 81 02 75 01 95 03 81 03 05 01 15 00 26 45 05 75 10 55 0e 65 11 09 30 35 00 46 64 04 95 01 81 02 46 a2 02 26 29 03 09 31 81 02 c0 05 0d 55 0c 66 01 10 47 ff ff 00 00 27 ff ff 00 00 75 10 95 01 09 56 81 02 09 54 25 7f 95 01 75 08 81 02 05 09 09 01 25 01 75 01 95 01 81 02 95 07 81 03 05 0d 85 08 09 55 09 59 75 04 95 02 25 0f b1 02 85 0d 09 60 75 01 95 01 15 00 25 01 b1 02 95 07 b1 03 85 07 06 00 ff 09 c5 15 00 26 ff 00 75 08 96 00 01 b1 02 c0 05 0d 09 0e a1 01 85 04 09 22 a1 02 09 52 15 00 25 0a 75 08 95 01 b1 02 c0 09 22 a1 00 85 06 09 57 09 58 75 01 95 02 25 01 b1 02 95 06 b1 03 c0 c0 06 00 ff 09 01 a1 01 85 09 09 02 15 00 26 ff 00 75 08 95 14 91 02 85 0a 09 03 15 00 26 ff 00 75 08 95 14 91 02 85 0b 09 04 15 00 26 ff 00 75 08 95 3d 81 02 85 0c 09 05 15 00 26 ff 00 75 08 95 3d 81 02 85 0f 09 06 15 00 26 ff 00 75 08 95 03 b1 02 85 0e 09 07 15 00 26 ff 00 75 08 95 01 b1 02 c0
```

- the first 2 char (`R:`) indicate that we are going to provide the report descriptor
- then the next number gives the size of the report descriptor
- then we get `size` bytes in hexadecimal value

Often (but not always), we have the human translation above the raw report
descriptor as shown above.

#### hid-recorder events

The HID events are using the following form:

```
# ReportID: 3 / Confidence: 1 | Tip Switch: 1 | Contact Id:  0 | # | X:    474 | Y:    335
#             | Confidence: 0 | Tip Switch: 0 | Contact Id:  0 | # | X:      0 | Y:      0
#             | Confidence: 0 | Tip Switch: 0 | Contact Id:  0 | # | X:      0 | Y:      0
#             | Confidence: 0 | Tip Switch: 0 | Contact Id:  0 | # | X:      0 | Y:      0
#             | Confidence: 0 | Tip Switch: 0 | Contact Id:  0 | # | X:      0 | Y:      0 | Scan Time:  37929 | Contact Count:    1 | Button: 0 | #
E: 000085.391130 30 03 03 da 01 4f 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 29 94 01 00
```

- the first 2 chars (`E:`) indicate the type "event"
- then we have a timestamp (`000085.391130`) in seconds
- then the size of the report, as decimal value
- then the report, with the first byte being the report ID when the report descriptor uses them

#### hid-recorder file format specification

The complete hid-recorder file format includes these line types:

- `# lines` - Comments providing human-readable interpretation of the data
- `D: <number>` - Device identifier when recording from multiple hidraw nodes
- `R: <size> <hex_data>` - Report descriptor with size followed by hexadecimal dump
- `N: <device_name>` - Common name of the device
- `P: <physical_path>` - Physical path to the device
- `I: <bus> <vendor_id> <product_id>` - Bus type and device identifiers
- `E: <timestamp> <size> <hex_report>` - Event with timestamp in seconds, report size, and hexadecimal report data
