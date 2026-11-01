//! One request/response round trip over the agent's control IPC: write one
//! newline-terminated JSON request, signal end of input, read one
//! newline-terminated JSON `Response`. The caller opens the socket or pipe.

use crate::control_proto::{Request, Response};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub async fn exchange<S>(stream: S, req: &Request) -> std::io::Result<Response>
where
    S: AsyncRead + AsyncWrite,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;
    wr.shutdown().await.ok();
    let mut line = String::new();
    BufReader::new(rd).read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}
