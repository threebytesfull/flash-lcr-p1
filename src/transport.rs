use std::time::{Duration, Instant};

pub trait Transport {
    fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()>;
    /// Read all available bytes, waiting up to `timeout`. Returns empty Vec on timeout.
    fn read_with_timeout(&mut self, timeout: Duration) -> anyhow::Result<Vec<u8>>;
}

pub struct SerialTransport {
    port: Box<dyn serialport::SerialPort>,
}

impl SerialTransport {
    pub fn new(port: Box<dyn serialport::SerialPort>) -> Self {
        Self { port }
    }
}

impl Transport for SerialTransport {
    fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        use std::io::Write;
        self.port.write_all(data)?;
        Ok(())
    }

    fn read_with_timeout(&mut self, timeout: Duration) -> anyhow::Result<Vec<u8>> {
        use std::io::Read;
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 256];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(vec![]);
            }
            self.port
                .set_timeout(remaining.min(Duration::from_millis(100)))?;
            match self.port.read(&mut buf) {
                Ok(0) => return Ok(vec![]),
                Ok(n) => return Ok(buf[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    if Instant::now() >= deadline {
                        return Ok(vec![]);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
pub struct MockTransport {
    pub written: Vec<Vec<u8>>,
    responses: std::collections::VecDeque<Vec<u8>>,
}

#[cfg(test)]
impl MockTransport {
    pub fn new(responses: Vec<Vec<u8>>) -> Self {
        Self {
            written: Vec::new(),
            responses: responses.into(),
        }
    }
}

#[cfg(test)]
impl Transport for MockTransport {
    fn write_all(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.written.push(data.to_vec());
        Ok(())
    }

    fn read_with_timeout(&mut self, _timeout: Duration) -> anyhow::Result<Vec<u8>> {
        Ok(self.responses.pop_front().unwrap_or_default())
    }
}

#[cfg(test)]
pub struct FailingTransport;

#[cfg(test)]
impl Transport for FailingTransport {
    fn write_all(&mut self, _data: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("simulated write failure")
    }

    fn read_with_timeout(&mut self, _timeout: Duration) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("simulated read failure")
    }
}
