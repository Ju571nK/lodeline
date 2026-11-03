//! Named-pipe server instances for the agent's pipes. The first instance claims
//! the name (`first_pipe_instance(true)`), and every instance carries an
//! explicit DACL: [`HOOK_SDDL`] lets a hook in a standard user session reach an
//! agent that runs as a service, and [`CONTROL_SDDL`] keeps the control pipe to
//! the accounts that may change the agent's state.
use lodeline_core::hook_proto::PIPE_CLIENT_ACCESS;
use std::io;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

// SYSTEM, Administrators and the owner get full control. Authenticated users get 0x12019b (`PIPE_CLIENT_ACCESS`), read/write without FILE_CREATE_PIPE_INSTANCE, so only the agent adds instances.
pub(crate) const HOOK_SDDL: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;0x12019b;;;AU)";

// The hook grants minus AU. Every control request needs read/write, which the default pipe DACL never gave other users, so no caller loses access.
pub(crate) const CONTROL_SDDL: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";

// A restarted agent can start while the previous one still drains its pipes, so
// the retries outlast that drain: 11 waits of 500 ms is 5.5 s.
pub(crate) const NAME_IN_USE_TRIES: u32 = 12;
#[cfg(not(test))]
pub(crate) const NAME_IN_USE_WAIT: Duration = Duration::from_millis(500);
#[cfg(test)]
pub(crate) const NAME_IN_USE_WAIT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const _: () = assert!(
    NAME_IN_USE_WAIT.as_millis() * (NAME_IN_USE_TRIES as u128 - 1)
        > crate::ipc_lifecycle::DRAIN_TIMEOUT.as_millis()
);

/// [`first_instance`], retried while the name is in use. `Ok(None)` means
/// shutdown came first. The error after the last try still satisfies
/// [`name_in_use`] when the name stayed taken.
pub async fn claim(
    name: &str,
    sddl: &str,
    shutdown: &CancellationToken,
) -> io::Result<Option<NamedPipeServer>> {
    for _ in 1..NAME_IN_USE_TRIES {
        match first_instance(name, sddl) {
            Err(e) if name_in_use(&e) => {}
            done => return done.map(Some),
        }
        tokio::select! {
            _ = shutdown.cancelled() => return Ok(None),
            _ = tokio::time::sleep(NAME_IN_USE_WAIT) => {}
        }
    }
    first_instance(name, sddl).map(Some)
}

/// Claims `name`. Fails when another process already serves it; see [`name_in_use`].
pub fn first_instance(name: &str, sddl: &str) -> io::Result<NamedPipeServer> {
    create(name, true, sddl)
}

/// Adds an instance to a pipe this process already owns.
pub fn next_instance(name: &str, sddl: &str) -> io::Result<NamedPipeServer> {
    create(name, false, sddl)
}

/// Opens `name` as a client with [`PIPE_CLIENT_ACCESS`] rather than generic
/// read/write, at `SECURITY_IDENTIFICATION`: the server may identify the caller
/// but cannot act as it.
pub fn open_client(name: &str) -> io::Result<NamedPipeClient> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION};
    let file = std::fs::OpenOptions::new()
        .access_mode(PIPE_CLIENT_ACCESS)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)?;
    // SAFETY: the handle is a named-pipe client opened for overlapped I/O, and
    // `into_raw_handle` hands its sole ownership to the client.
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
}

/// True when [`first_instance`] failed because the name is taken.
pub fn name_in_use(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(c) if c == ERROR_ACCESS_DENIED as i32 || c == ERROR_PIPE_BUSY as i32)
}

fn create(name: &str, first: bool, sddl: &str) -> io::Result<NamedPipeServer> {
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES and `sd` outlives the call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .access_inbound(true)
            .access_outbound(true)
            .create_with_security_attributes_raw(name, std::ptr::addr_of_mut!(attrs).cast())
    }
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call, `sd` is a valid
        // out-pointer, and the size out-parameter is optional.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW,
        // which documents LocalFree as its release.
        unsafe { LocalFree(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    fn unique_name() -> String {
        format!(r"\\.\pipe\lodeline-test-{}", uuid::Uuid::now_v7())
    }

    #[test]
    fn sddl_parses_and_grants_the_hook_access_mask() {
        assert!(SecurityDescriptor::from_sddl(HOOK_SDDL).is_ok());
        assert!(HOOK_SDDL.contains(&format!("{PIPE_CLIENT_ACCESS:#x}")));
        assert!(SecurityDescriptor::from_sddl(CONTROL_SDDL).is_ok());
        assert!(
            !CONTROL_SDDL.contains(";AU)"),
            "control pipe grants no other users"
        );
    }

    #[tokio::test]
    async fn second_first_instance_reports_name_in_use() {
        let name = unique_name();
        let _other = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let err = first_instance(&name, HOOK_SDDL).unwrap_err();
        assert!(name_in_use(&err), "{err:?}");
    }

    #[tokio::test]
    async fn client_mask_connects_but_cannot_add_instances() {
        let name = unique_name();
        // The only ACE grants everyone, this process included, the client mask. Implicit owner rights are READ_CONTROL and WRITE_DAC only.
        let _server = create(&name, true, "D:(A;;0x12019b;;;WD)").unwrap();

        let added = create(&name, false, "D:(A;;0x12019b;;;WD)").unwrap_err();
        assert_eq!(added.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        std::fs::OpenOptions::new()
            .access_mode(PIPE_CLIENT_ACCESS)
            .open(&name)
            .expect("hook access mask connects");
    }

    #[tokio::test]
    async fn owner_opens_the_control_pipe_with_the_client_mask() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let name = unique_name();
        let mut server = first_instance(&name, CONTROL_SDDL).unwrap();
        let mut client = open_client(&name).expect("owner connects with the client mask");
        server.connect().await.unwrap();
        next_instance(&name, CONTROL_SDDL).expect("owner adds instances");

        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }
}
