mod protocol;
mod transport;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serialport::SerialPortType;

use protocol::{ResponseStatus, read_response, send_handshake, upload_firmware};
use transport::SerialTransport;

const WCH_VID: u16 = 0x1A86;

#[derive(Parser)]
#[command(version, about = "Flash firmware to LCR-P1 over USB serial")]
struct Cli {
    /// Path to firmware .bin file (or .zip containing a single .bin)
    firmware: Option<PathBuf>,

    /// Serial port to use (e.g. /dev/tty.usbserial-110)
    #[arg(short, long)]
    port: Option<String>,

    /// List available serial ports and exit
    #[arg(short, long)]
    list: bool,

    /// Validate firmware and show what would be sent, without touching hardware
    #[arg(long)]
    dry_run: bool,

    /// Print hex dumps of handshake, packet sample, and raw response
    #[arg(short, long)]
    verbose: bool,
}

fn list_ports() -> anyhow::Result<()> {
    let ports = serialport::available_ports().context("Failed to enumerate serial ports")?;
    if ports.is_empty() {
        println!("No serial ports found.");
        return Ok(());
    }
    for p in &ports {
        match &p.port_type {
            SerialPortType::UsbPort(info) => {
                let wch = if info.vid == WCH_VID {
                    " [likely WCH CH34x]"
                } else {
                    ""
                };
                println!(
                    "{} — USB VID:{:04X} PID:{:04X} mfr={} product={}{}",
                    p.port_name,
                    info.vid,
                    info.pid,
                    info.manufacturer.as_deref().unwrap_or("?"),
                    info.product.as_deref().unwrap_or("?"),
                    wch,
                );
            }
            _ => println!("{}", p.port_name),
        }
    }
    Ok(())
}

/// On macOS each USB serial device appears twice:
///
/// * `/dev.tty.*` (block on open until carrier detect)
/// * `/dev/cu.*` (opens immediately, for when we're initiating the connection)
///
/// Drop any `tty.*` entry when a corresponding `cu.*` sibling exists.
#[cfg(target_os = "macos")]
fn deduplicate_macos_tty(
    ports: Vec<serialport::SerialPortInfo>,
) -> Vec<serialport::SerialPortInfo> {
    let cu_names: std::collections::HashSet<String> = ports
        .iter()
        .filter_map(|p| p.port_name.strip_prefix("/dev/cu.").map(String::from))
        .collect();
    ports
        .into_iter()
        .filter(|p| {
            p.port_name
                .strip_prefix("/dev/tty.")
                .is_none_or(|suffix| !cu_names.contains(suffix))
        })
        .collect()
}

fn auto_select_port() -> anyhow::Result<String> {
    let raw = serialport::available_ports().context("Failed to enumerate serial ports")?;
    #[cfg(target_os = "macos")]
    let ports = deduplicate_macos_tty(raw);
    #[cfg(not(target_os = "macos"))]
    let ports = raw;

    let wch: Vec<_> = ports
        .iter()
        .filter(|p| matches!(&p.port_type, SerialPortType::UsbPort(i) if i.vid == WCH_VID))
        .collect();

    if wch.is_empty() {
        match ports.as_slice() {
            [] => bail!("No serial ports found. Connect the device and try again."),
            [one] => {
                println!("Auto-selected port: {}", one.port_name);
                return Ok(one.port_name.clone());
            }
            many => {
                eprintln!("Multiple serial ports found; specify one with --port:");
                for p in many {
                    eprintln!("  {}", p.port_name);
                }
                bail!("Ambiguous port selection");
            }
        }
    }

    match wch.as_slice() {
        [one] => {
            println!("Auto-selected port: {}", one.port_name);
            Ok(one.port_name.clone())
        }
        many => {
            eprintln!("Multiple WCH ports found; specify one with --port:");
            for p in many {
                eprintln!("  {}", p.port_name);
            }
            bail!("Ambiguous port selection");
        }
    }
}

/// Extract the single `.bin` file from a zip archive given as raw bytes.
/// Errors if there are zero or multiple `.bin` entries, or if the extracted
/// length does not match the size declared in the zip central directory.
#[cfg(feature = "zip")]
fn extract_bin_from_zip(zip_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("Failed to open zip archive")?;
    // Collect (index, name) for every .bin entry in one pass.
    let bins: Vec<(usize, String)> = (0..archive.len())
        .filter_map(|i| {
            archive.by_index(i).ok().and_then(|f| {
                let name = f.name().to_string();
                if name.to_lowercase().ends_with(".bin") {
                    Some((i, name))
                } else {
                    None
                }
            })
        })
        .collect();
    match bins.as_slice() {
        [] => bail!("No .bin files found in zip archive"),
        [(idx, name)] => {
            let mut f = archive
                .by_index(*idx)
                .with_context(|| format!("Cannot open {name} in zip"))?;
            let expected_len =
                usize::try_from(f.size()).context("Zip entry size overflows usize")?;
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            anyhow::ensure!(
                data.len() == expected_len,
                "Extracted {} bytes from {name} but zip metadata declares {} bytes",
                data.len(),
                expected_len,
            );
            Ok(data)
        }
        many => bail!(
            "Multiple .bin files in zip; not sure which to use: {}",
            many.iter()
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn load_firmware(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;

    let is_zip = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
        || raw.starts_with(b"PK\x03\x04");

    if is_zip {
        #[cfg(feature = "zip")]
        return extract_bin_from_zip(&raw);
        #[cfg(not(feature = "zip"))]
        bail!("Zip support not compiled in (enable the 'zip' feature)");
    }

    Ok(raw)
}

#[cfg(test)]
#[cfg(feature = "zip")]
mod zip_tests {
    use super::extract_bin_from_zip;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(cursor);
        for (name, data) in files {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    #[test]
    fn test_zip_single_bin_extracted_correctly() {
        let payload = b"hello firmware world";
        let zip = make_zip(&[("firmware.bin", payload)]);
        let result = extract_bin_from_zip(&zip).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_zip_non_bin_files_ignored() {
        let payload = b"real firmware bytes";
        let zip = make_zip(&[("readme.txt", b"ignore me"), ("fw.bin", payload)]);
        let result = extract_bin_from_zip(&zip).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_zip_bin_extension_case_insensitive() {
        let payload = b"case test";
        let zip = make_zip(&[("FIRMWARE.BIN", payload)]);
        let result = extract_bin_from_zip(&zip).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_zip_no_bin_errors() {
        let zip = make_zip(&[("readme.txt", b"no firmware here")]);
        let err = extract_bin_from_zip(&zip).unwrap_err();
        assert!(err.to_string().contains("No .bin files"), "{err}");
    }

    #[test]
    fn test_zip_multiple_bins_errors() {
        let zip = make_zip(&[("a.bin", b"one"), ("b.bin", b"two")]);
        let err = extract_bin_from_zip(&zip).unwrap_err();
        assert!(err.to_string().contains("Multiple .bin files"), "{err}");
        assert!(err.to_string().contains("a.bin"), "{err}");
        assert!(err.to_string().contains("b.bin"), "{err}");
    }

    #[test]
    fn test_zip_extracted_length_matches_content() {
        // Verify the size-check assertion passes for a well-formed zip.
        let payload: Vec<u8> = (0u8..=255).collect();
        let zip = make_zip(&[("fw.bin", &payload)]);
        let result = extract_bin_from_zip(&zip).unwrap();
        assert_eq!(result.len(), payload.len());
        assert_eq!(result, payload);
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod dedup_tests {
    use super::deduplicate_macos_tty;
    use serialport::{SerialPortInfo, SerialPortType};

    fn make_port(name: &str) -> SerialPortInfo {
        SerialPortInfo {
            port_name: name.to_string(),
            port_type: SerialPortType::Unknown,
        }
    }

    #[test]
    fn test_tty_dropped_when_cu_sibling_exists() {
        let ports = vec![
            make_port("/dev/cu.usbserial-110"),
            make_port("/dev/tty.usbserial-110"),
        ];
        let result = deduplicate_macos_tty(ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port_name, "/dev/cu.usbserial-110");
    }

    #[test]
    fn test_tty_kept_when_no_cu_sibling() {
        let ports = vec![make_port("/dev/tty.usbserial-110")];
        let result = deduplicate_macos_tty(ports);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].port_name, "/dev/tty.usbserial-110");
    }

    #[test]
    fn test_cu_always_kept() {
        let ports = vec![make_port("/dev/cu.usbserial-110")];
        let result = deduplicate_macos_tty(ports);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_non_dev_ports_unaffected() {
        let ports = vec![make_port("COM3"), make_port("/dev/ttyUSB0")];
        let result = deduplicate_macos_tty(ports);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_multiple_pairs_all_deduped() {
        let ports = vec![
            make_port("/dev/cu.usbserial-1"),
            make_port("/dev/tty.usbserial-1"),
            make_port("/dev/cu.usbserial-2"),
            make_port("/dev/tty.usbserial-2"),
        ];
        let result = deduplicate_macos_tty(ports);
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|p| p.port_name.starts_with("/dev/cu.")));
    }

    #[test]
    fn test_empty_input() {
        let result = deduplicate_macos_tty(vec![]);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod load_firmware_tests {
    use super::load_firmware;
    use std::io::Write;

    fn write_temp(suffix: &str, data: &[u8]) -> (tempfile::NamedTempFile, std::path::PathBuf) {
        let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        f.write_all(data).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[test]
    fn test_load_plain_bin() {
        let payload = b"raw firmware bytes";
        let (_f, path) = write_temp(".bin", payload);
        let result = load_firmware(&path).unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn test_load_nonexistent_file_errors() {
        let path = std::path::PathBuf::from("/nonexistent/path/fw.bin");
        assert!(load_firmware(&path).is_err());
    }

    #[test]
    fn test_load_file_without_zip_extension_treated_as_bin() {
        // A file with no .zip extension and no PK magic is loaded as raw bytes.
        let payload = b"definitely not a zip";
        let (_f, path) = write_temp(".bin", payload);
        let result = load_firmware(&path).unwrap();
        assert_eq!(result, payload);
    }

    #[cfg(feature = "zip")]
    #[test]
    fn test_load_zip_by_extension() {
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;

        let payload = b"zipped firmware";
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(cursor);
        zw.start_file("fw.bin", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(payload).unwrap();
        let zip_bytes = zw.finish().unwrap().into_inner();

        let (_f, path) = write_temp(".zip", &zip_bytes);
        let result = load_firmware(&path).unwrap();
        assert_eq!(result, payload);
    }

    #[cfg(feature = "zip")]
    #[test]
    fn test_load_zip_by_magic_bytes() {
        // File has no .zip extension but starts with PK magic — should be treated as zip.
        use std::io::Write as _;
        use zip::write::SimpleFileOptions;

        let payload = b"magic bytes firmware";
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zw = zip::ZipWriter::new(cursor);
        zw.start_file("fw.bin", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(payload).unwrap();
        let zip_bytes = zw.finish().unwrap().into_inner();

        // Write with a .bin extension so only the magic bytes trigger zip detection.
        let (_f, path) = write_temp(".bin", &zip_bytes);
        let result = load_firmware(&path).unwrap();
        assert_eq!(result, payload);
    }
}

#[cfg(test)]
mod hex_dump_tests {
    use super::hex_dump;

    fn dump(label: &str, data: &[u8]) -> String {
        let mut out = Vec::new();
        hex_dump(label, data, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn test_label_appears_on_first_line_only() {
        let output = dump("TX", &[0x01, 0x02, 0x03]);
        assert!(output.starts_with("TX:"), "{output:?}");
    }

    #[test]
    fn test_subsequent_lines_have_blank_prefix() {
        let data: Vec<u8> = (0x00..=0x1F).collect(); // 32 bytes → 2 lines
        let output = dump("Label", &data);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("Label:"), "{:?}", lines[0]);
        assert!(lines[1].starts_with("     :"), "{:?}", lines[1]);
    }

    #[test]
    fn test_columns_align() {
        let data: Vec<u8> = (0x00..=0x1F).collect(); // 32 bytes → 2 lines
        let output = dump("TX", &data);
        let cols: Vec<usize> = output.lines().map(|l| l.find(':').unwrap()).collect();
        assert!(
            cols.windows(2).all(|w| w[0] == w[1]),
            "colons misaligned: {output:?}"
        );
    }

    #[test]
    fn test_exactly_16_bytes_is_one_line() {
        let data: Vec<u8> = (0x00..0x10).collect();
        let output = dump("TX", &data);
        assert_eq!(
            output.trim_end(),
            "TX: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
        );
    }

    #[test]
    fn test_partial_last_line_not_padded() {
        let data: Vec<u8> = (0x00..0x13).collect(); // 19 bytes → 16 + 3
        let output = dump("TX", &data);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], "  : 10 11 12");
    }

    #[test]
    fn test_empty_data_produces_no_output() {
        assert!(dump("TX", &[]).is_empty());
    }
}

fn open_transport(port_name: &str) -> anyhow::Result<SerialTransport> {
    let port = serialport::new(port_name, 115_200)
        .timeout(Duration::from_secs(5))
        .open()
        .with_context(|| format!("Failed to open {port_name}"))?;
    Ok(SerialTransport::new(port))
}

fn hex_dump(label: &str, data: &[u8], out: &mut impl std::io::Write) -> std::io::Result<()> {
    let pad = " ".repeat(label.len());
    let prefixes = std::iter::once(label).chain(std::iter::repeat(pad.as_str()));
    for (prefix, chunk) in prefixes.zip(data.chunks(16)) {
        let hex = chunk
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(out, "{prefix}: {hex}")?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.list {
        return list_ports();
    }

    let firmware_path = cli
        .firmware
        .as_ref()
        .context("Firmware path required (or use --list)")?;

    let firmware = load_firmware(firmware_path)?;

    let chunk_count = firmware.chunks(512).count();
    let padding = protocol::needs_padding_packet(firmware.len());
    let total_packets = chunk_count + usize::from(padding);

    if cli.dry_run {
        println!("Firmware: {} bytes", firmware.len());
        println!("Data packets: {chunk_count}");
        println!("Padding packet: {padding}");
        println!("Total packets: {total_packets}");
        return Ok(());
    }

    let port_name = match &cli.port {
        Some(p) => p.clone(),
        None => auto_select_port()?,
    };

    // open, send handshake, close
    {
        let mut transport = open_transport(&port_name)?;
        let handshake = [0xAC, 0x55, 0x02, 0x03];
        if cli.verbose {
            let mut stdout = std::io::stdout();
            hex_dump("Handshake TX", &handshake, &mut stdout)?;
        }
        send_handshake(&mut transport)?;
    }

    thread::sleep(Duration::from_millis(10));

    // reopen, upload, read response
    {
        let mut transport = open_transport(&port_name)?;

        let pb = ProgressBar::new(total_packets as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} packets",
            )
            .unwrap()
            .progress_chars("=>-"),
        );

        let mut first_packet_logged = false;
        upload_firmware(&mut transport, &firmware, |done, _total| {
            if cli.verbose && !first_packet_logged {
                first_packet_logged = true;
                hex_dump(
                    "First packet",
                    &firmware[..usize::min(512, firmware.len())],
                    &mut std::io::stdout(),
                )
                .ok();
            }
            pb.set_position(done as u64);
        })?;
        pb.finish_with_message("Upload complete");

        match read_response(&mut transport)? {
            ResponseStatus::Success => {
                println!("Success: device acknowledged firmware upload.");
                if cli.verbose {
                    println!("(Response matched 0x55 0x03)");
                }
            }
            ResponseStatus::Failure(bytes) => {
                if cli.verbose {
                    let mut stdout = std::io::stdout();
                    hex_dump("Response RX", &bytes, &mut stdout)?;
                }
                bail!("Device returned failure response");
            }
            ResponseStatus::Timeout => {
                bail!("Timed out waiting for device response");
            }
        }
    }

    Ok(())
}
