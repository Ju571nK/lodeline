//! IPC client: connects to lodeline-agent's control socket/pipe and
//! invokes `apply_policy`.

use crate::wire::SignedPolicyResponse;
pub use lodeline_core::control_proto::ApplyPolicyResult;
use lodeline_core::event::PolicySignatureInvalidReason;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum AgentRequest<'a> {
    ApplyPolicy { response: &'a SignedPolicyResponse },
    ApplyRulePacks { response: &'a SignedPolicyResponse },
}

#[derive(Deserialize, Debug)]
pub struct AgentResponse {
    pub ok: bool,
    pub apply_policy: Option<ApplyPolicyResult>,
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("connect {path}: {source}")]
    Connect {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("response parse: {0}")]
    Parse(#[from] serde_json::Error),
}

/// What the agent's answer settles about one signed document.
#[derive(Debug, PartialEq, Eq)]
pub enum Settlement {
    Applied,
    /// Only a new document can change this answer.
    Refused(PolicySignatureInvalidReason),
    /// The keystore decided this answer, and the keystore can change while the
    /// document stays the same. An agent that could not load its keystore lands here.
    RefusedForNow(PolicySignatureInvalidReason),
    /// The agent gave no decision: it was unreachable, failed, or answered nonsense.
    Undecided(String),
}

impl From<Result<AgentResponse, IpcError>> for Settlement {
    fn from(answer: Result<AgentResponse, IpcError>) -> Self {
        use PolicySignatureInvalidReason::*;
        match answer {
            Ok(AgentResponse {
                ok: true,
                apply_policy: Some(ApplyPolicyResult::Accepted { .. }),
                ..
            }) => Settlement::Applied,
            Ok(AgentResponse {
                apply_policy: Some(ApplyPolicyResult::Rejected { reason }),
                ..
            }) => match reason {
                VersionRegression | SignatureInvalid | Expired | ParseFailed => {
                    Settlement::Refused(reason)
                }
                PubkeyUnknown | PubkeyInactive => Settlement::RefusedForNow(reason),
            },
            Ok(other) => Settlement::Undecided(format!("{other:?}")),
            Err(e) => Settlement::Undecided(e.to_string()),
        }
    }
}

#[cfg(unix)]
pub async fn apply_policy(
    socket_path: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|source| IpcError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (rd, mut wr) = stream.into_split();
    let req = AgentRequest::ApplyPolicy { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    wr.write_all(&req_bytes).await?;
    wr.shutdown().await.ok();
    let mut buf = String::new();
    BufReader::new(rd).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}

/// Sends a fresh rule-pack bundle to the agent. Mirrors [`apply_policy`]:
/// same socket protocol, just the `ApplyRulePacks` request variant.
#[cfg(unix)]
pub async fn apply_rule_packs(
    socket_path: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|source| IpcError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (rd, mut wr) = stream.into_split();
    let req = AgentRequest::ApplyRulePacks { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    wr.write_all(&req_bytes).await?;
    wr.shutdown().await.ok();
    let mut buf = String::new();
    BufReader::new(rd).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}

#[cfg(windows)]
pub async fn apply_policy(
    pipe_name: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    let pipe_str = pipe_name.to_string_lossy().to_string();
    let mut client = ClientOptions::new()
        .open(pipe_str.as_str())
        .map_err(|source| IpcError::Connect {
            path: pipe_name.to_path_buf(),
            source,
        })?;
    let req = AgentRequest::ApplyPolicy { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    client.write_all(&req_bytes).await?;
    client.flush().await?;
    let mut buf = String::new();
    BufReader::new(&mut client).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}

/// Sends a fresh rule-pack bundle to the agent. Mirrors [`apply_policy`]:
/// same pipe protocol, just the `ApplyRulePacks` request variant.
#[cfg(windows)]
pub async fn apply_rule_packs(
    pipe_name: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    let pipe_str = pipe_name.to_string_lossy().to_string();
    let mut client = ClientOptions::new()
        .open(pipe_str.as_str())
        .map_err(|source| IpcError::Connect {
            path: pipe_name.to_path_buf(),
            source,
        })?;
    let req = AgentRequest::ApplyRulePacks { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    client.write_all(&req_bytes).await?;
    client.flush().await?;
    let mut buf = String::new();
    BufReader::new(&mut client).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settle(answer: &str) -> Settlement {
        let parsed = serde_json::from_str::<AgentResponse>(answer).map_err(IpcError::from);
        Settlement::from(parsed)
    }

    fn refusal(reason: &str) -> Settlement {
        settle(&format!(
            r#"{{"ok":false,"apply_policy":{{"outcome":"rejected","reason":"{reason}"}}}}"#
        ))
    }

    #[test]
    fn an_accepted_document_is_applied() {
        assert_eq!(
            settle(
                r#"{"ok":true,"apply_policy":{"outcome":"accepted","applied_policy_version":5}}"#
            ),
            Settlement::Applied
        );
    }

    #[test]
    fn only_a_version_the_agent_already_passed_is_final() {
        assert_eq!(
            refusal("version_regression"),
            Settlement::Refused(PolicySignatureInvalidReason::VersionRegression)
        );
    }

    #[test]
    fn a_refusal_decided_by_the_host_or_the_agent_build_is_not_final() {
        use PolicySignatureInvalidReason::*;
        for (wire, reason) in [
            ("pubkey_unknown", PubkeyUnknown),
            ("pubkey_inactive", PubkeyInactive),
            ("signature_invalid", SignatureInvalid),
            ("expired", Expired),
            ("parse_failed", ParseFailed),
        ] {
            assert_eq!(refusal(wire), Settlement::RefusedForNow(reason));
        }
    }

    #[test]
    fn no_decision_from_the_agent_is_undecided() {
        for answer in [
            r#"{"ok":false,"apply_policy":null,"error":"internal: atomic disk write"}"#,
            r#"{"ok":false,"error":"unknown variant `apply_rule_packs`"}"#,
            r#"{"ok":true}"#,
            r#"{"ok":false,"apply_policy":{"outcome":"accepted","applied_policy_version":5}}"#,
            "",
            "not json",
            r#"{"ok":false,"apply_policy":{"outcome":"rejected","reason":"from_a_newer_agent"}}"#,
        ] {
            assert!(
                matches!(settle(answer), Settlement::Undecided(_)),
                "{answer}"
            );
        }
    }

    #[test]
    fn an_unreachable_agent_is_undecided() {
        let unreachable = Err(IpcError::Connect {
            path: "/run/control.sock".into(),
            source: std::io::ErrorKind::NotFound.into(),
        });
        assert!(matches!(
            Settlement::from(unreachable),
            Settlement::Undecided(_)
        ));
    }
}
