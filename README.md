# flash-lcr-p1

[![Build Status](https://github.com/threebytesfull/flash-lcr-p1/actions/workflows/ci.yml/badge.svg)](https://github.com/threebytesfull/flash-lcr-p1/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/flash-lcr-p1.svg)](https://crates.io/crates/flash-lcr-p1)
[![codecov](https://codecov.io/gh/threebytesfull/flash-lcr-p1/branch/main/graph/badge.svg)](https://codecov.io/gh/threebytesfull/flash-lcr-p1)
[![Licence: MIT OR Apache-2.0](https://img.shields.io/badge/licence-MIT%20OR%20Apache--2.0-blue.svg)](#licence)

A command-line tool to flash firmware to the **Fnirsi LCR-P1** LCR meter over USB serial (CH340/CH341 chip).

## Installation

### Via Homebrew (macOS / Linux)

```sh
brew install threebytesfull/tap/flash-lcr-p1
```

### Via cargo

```sh
cargo install flash-lcr-p1
```

### Pre-built binaries

Download the latest binary for your platform from the [GitHub Releases](https://github.com/threebytesfull/flash-lcr-p1/releases) page.

## Usage

```
Flash firmware to LCR-P1 over USB serial

Usage: flash-lcr-p1 [OPTIONS] [FIRMWARE]

Arguments:
  [FIRMWARE]  Path to firmware .bin file (or .zip containing a single .bin)

Options:
  -p, --port <PORT>  Serial port to use (e.g. /dev/tty.usbserial-110)
  -l, --list         List available serial ports and exit
      --dry-run      Validate firmware and show what would be sent, without touching hardware
  -v, --verbose      Print hex dumps of handshake, packet sample, and raw response
  -h, --help         Print help
  -V, --version      Print version
```

### Examples

```sh
# List available serial ports
flash-lcr-p1 --list

# Flash firmware (auto-detects the CH34x port)
flash-lcr-p1 firmware.bin

# Flash firmware on a specific port (macOS prefers /dev/cu.*)
flash-lcr-p1 --port /dev/cu.usbserial-110 firmware.bin

# Flash from a zip archive containing a single .bin file
flash-lcr-p1 firmware.zip

# Validate firmware without touching hardware
flash-lcr-p1 --dry-run firmware.bin
```

## Platform notes

**macOS** - tested. The device is auto-detected by its WCH VID.

**Linux** - should work. The CH341 kernel module (`ch341`) is included in the mainline kernel; plug in the device and it should appear as `/dev/ttyUSB0` or similar.

**Windows** - should work, but requires the WCH CH340/CH341 driver to be installed first. Without it the device won't appear as a COM port. Drivers are available from [WCH's website](https://www.wch-ic.com/downloads/CH341SER_EXE.html). Once installed, pass the COM port explicitly if auto-detection doesn't pick it up: `flash-lcr-p1 --port COM3 firmware.bin`.

**Auto-detection note** - if there are multiple serial ports present, auto-detection will ask you to specify `--port`.

## Building from source

Requires Rust 1.85 or later.

```sh
git clone https://github.com/threebytesfull/flash-lcr-p1
cd flash-lcr-p1
cargo build --release
# Binary is at target/release/flash-lcr-p1
```

## Licence

Licensed under either of:

- [MIT licence](LICENSE-MIT)
- [Apache Licence, Version 2.0](LICENSE-APACHE)

at your option.
