use std::time::{Duration, Instant};

use crate::transport::Transport;

// Apparent protocol from the original BootTool.exe:
//
// Initial handshake:
// - open serial port at 115200 8N1, no flow control
// - send 4 bytes [0xAC, 0x55, 0x02, 0x03]
// - close port (don't expect a response) and wait at least 10ms
//
// Upload firmware:
// - reopen serial port
// - send firmware as 512-bytes packets, maybe with final padding packet
//
// Read response:
// - wait up to 20 seconds for device response (while it presumably flashes)
// - expect [0x??, 0x55, 0x03] for success, anything else or nothing is failure
//
// Packet construction:
// - 512-byte buffer filled with 0xFF except last 4 bytes always [0x78, 0x56, 0x34, 0x12]
// - write 512-byte chunks of firmware into buffer, starting at offset 0
// - overwriting the trailer for non-final packets appears to be fine
// - final packet may or may not have real data but must have intact trailer

#[derive(Debug)]
pub enum ResponseStatus {
    Success,
    Failure(Vec<u8>),
    Timeout,
}

pub fn send_handshake(transport: &mut impl Transport) -> anyhow::Result<()> {
    transport.write_all(&[0xAC, 0x55, 0x02, 0x03])
}

pub fn build_packet(firmware_chunk: &[u8]) -> [u8; 512] {
    let mut buf = [0xFFu8; 512];
    buf[508] = 0x78;
    buf[509] = 0x56;
    buf[510] = 0x34;
    buf[511] = 0x12;
    let n = firmware_chunk.len().min(512);
    buf[..n].copy_from_slice(&firmware_chunk[..n]);
    buf
}

pub fn needs_padding_packet(firmware_len: usize) -> bool {
    let rem = firmware_len % 512;
    rem >= 509 || rem == 0
}

pub fn upload_firmware(
    transport: &mut impl Transport,
    firmware: &[u8],
    mut progress_cb: impl FnMut(usize, usize),
) -> anyhow::Result<()> {
    let padding = needs_padding_packet(firmware.len());
    let data_chunks = firmware.chunks(512).count();
    let total = data_chunks + usize::from(padding);
    for (i, chunk) in firmware.chunks(512).enumerate() {
        let packet = build_packet(chunk);
        transport.write_all(&packet)?;
        progress_cb(i + 1, total);
    }
    if padding {
        let mut pad = [0xFFu8; 512];
        pad[508] = 0x78;
        pad[509] = 0x56;
        pad[510] = 0x34;
        pad[511] = 0x12;
        transport.write_all(&pad)?;
        progress_cb(total, total);
    }
    Ok(())
}

pub fn read_response(transport: &mut impl Transport) -> anyhow::Result<ResponseStatus> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let chunk = transport.read_with_timeout(remaining)?;
        if chunk.is_empty() {
            // Transport timed out with no data; stop waiting.
            break;
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= 3 {
            break;
        }
    }
    if bytes.is_empty() {
        return Ok(ResponseStatus::Timeout);
    }
    if bytes.len() >= 3 && bytes[1] == 0x55 && bytes[2] == 0x03 {
        Ok(ResponseStatus::Success)
    } else {
        Ok(ResponseStatus::Failure(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{FailingTransport, MockTransport};

    #[test]
    fn test_handshake() {
        let mut t = MockTransport::new(vec![]);
        send_handshake(&mut t).unwrap();
        assert_eq!(t.written, vec![vec![0xAC, 0x55, 0x02, 0x03]]);
    }

    #[test]
    fn test_packet_full() {
        let input = [0xAAu8; 512];
        let pkt = build_packet(&input);
        assert_eq!(&pkt[0..512], &input[..]);
    }

    #[test]
    fn test_packet_partial() {
        let input = [0xBBu8; 100];
        let pkt = build_packet(&input);
        assert_eq!(&pkt[0..100], &input[..]);
        assert!(pkt[100..508].iter().all(|&b| b == 0xFF));
        assert_eq!(&pkt[508..512], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_packet_boundary_508() {
        let input = [0xCCu8; 508];
        let pkt = build_packet(&input);
        assert_eq!(&pkt[0..508], &input[..]);
        assert_eq!(&pkt[508..512], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_packet_boundary_509() {
        let input = [0xDDu8; 509];
        let pkt = build_packet(&input);
        // Data (0..509) overwrites buf[508] (first trailer byte 0x78)
        assert_eq!(&pkt[0..509], &input[..]);
        // Remaining trailer bytes 509-511 are untouched
        assert_eq!(pkt[509], 0x56);
        assert_eq!(pkt[510], 0x34);
        assert_eq!(pkt[511], 0x12);
    }

    #[test]
    fn test_no_padding_needed() {
        assert!(!needs_padding_packet(508));
        assert!(!needs_padding_packet(1));
    }

    #[test]
    fn test_padding_needed_509() {
        assert!(needs_padding_packet(509));
    }

    #[test]
    fn test_padding_needed_511() {
        assert!(needs_padding_packet(511));
    }

    #[test]
    fn test_padding_needed_512() {
        assert!(needs_padding_packet(512));
    }

    #[test]
    fn test_padding_needed_1024() {
        assert!(needs_padding_packet(1024));
    }

    #[test]
    fn test_padding_not_needed_1() {
        assert!(!needs_padding_packet(1));
    }

    #[test]
    fn test_response_success() {
        let mut t = MockTransport::new(vec![vec![0x00, 0x55, 0x03]]);
        let r = read_response(&mut t).unwrap();
        assert!(matches!(r, ResponseStatus::Success));
    }

    #[test]
    fn test_response_failure() {
        let mut t = MockTransport::new(vec![vec![0x00, 0x00, 0x00]]);
        let r = read_response(&mut t).unwrap();
        assert!(matches!(r, ResponseStatus::Failure(_)));
    }

    #[test]
    fn test_response_timeout() {
        let mut t = MockTransport::new(vec![vec![]]);
        let r = read_response(&mut t).unwrap();
        assert!(matches!(r, ResponseStatus::Timeout));
    }

    #[test]
    fn test_response_success_split_reads() {
        // Response arrives in two chunks: [0x00] then [0x55, 0x03]
        let mut t = MockTransport::new(vec![vec![0x00], vec![0x55, 0x03]]);
        let r = read_response(&mut t).unwrap();
        assert!(matches!(r, ResponseStatus::Success));
    }

    #[test]
    fn test_response_success_byte_by_byte() {
        // Response arrives one byte at a time
        let mut t = MockTransport::new(vec![vec![0x01], vec![0x55], vec![0x03]]);
        let r = read_response(&mut t).unwrap();
        assert!(matches!(r, ResponseStatus::Success));
    }

    #[test]
    fn test_upload_write_error_propagated() {
        let firmware = vec![0u8; 100];
        let mut t = FailingTransport;
        let err = upload_firmware(&mut t, &firmware, |_, _| {}).unwrap_err();
        assert!(err.to_string().contains("simulated write failure"), "{err}");
    }

    #[test]
    fn test_read_response_transport_error_propagated() {
        let mut t = FailingTransport;
        let err = read_response(&mut t).unwrap_err();
        assert!(err.to_string().contains("simulated read failure"), "{err}");
    }

    #[test]
    fn test_upload_packet_count() {
        // 1024 bytes = 2 chunks, no padding (1024 % 512 == 0, so padding IS needed)
        let firmware = vec![0u8; 1024];
        let mut t = MockTransport::new(vec![]);
        upload_firmware(&mut t, &firmware, |_, _| {}).unwrap();
        // 2 data packets + 1 padding packet
        assert_eq!(t.written.len(), 3);

        // 100 bytes = 1 chunk, no padding (100 % 512 == 100, not >=509 and not 0)
        let firmware2 = vec![0u8; 100];
        let mut t2 = MockTransport::new(vec![]);
        upload_firmware(&mut t2, &firmware2, |_, _| {}).unwrap();
        assert_eq!(t2.written.len(), 1);
    }
}
