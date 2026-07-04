//! Length-prefixed JSON framing for the IPC socket.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME: usize = 1 << 24; // 16 MiB

pub async fn write_json<W, T>(w: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let len = (bytes.len() as u32).to_be_bytes();
    w.write_all(&len).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_json<R, T>(r: &mut R) -> io::Result<T>
where
    R: AsyncReadExt + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        n: u64,
        s: String,
    }

    #[tokio::test]
    async fn round_trip_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let sent = Msg {
            n: 42,
            s: "hello".into(),
        };
        write_json(&mut a, &sent).await.unwrap();
        let got: Msg = read_json(&mut b).await.unwrap();
        assert_eq!(sent, got);
    }

    #[tokio::test]
    async fn write_rejects_oversize() {
        // A value whose JSON exceeds MAX_FRAME is rejected before any bytes are
        // written, so the stream stays intact for the caller to recover.
        let (mut a, _b) = tokio::io::duplex(64);
        let big = "x".repeat(MAX_FRAME + 1);
        let err = write_json(&mut a, &big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_rejects_oversize_length_prefix() {
        // A length prefix beyond MAX_FRAME is rejected without allocating or
        // reading the claimed body.
        let (mut a, mut b) = tokio::io::duplex(64);
        let len = ((MAX_FRAME + 1) as u32).to_be_bytes();
        a.write_all(&len).await.unwrap();
        let got: io::Result<Msg> = read_json(&mut b).await;
        assert_eq!(got.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
