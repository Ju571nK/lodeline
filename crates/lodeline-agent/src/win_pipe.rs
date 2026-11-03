//! Named-pipe server instances for the hook pipes. The first instance claims
//! the name (`first_pipe_instance(true)`), and every instance carries an
//! explicit DACL so a hook in a standard user session can reach an agent that
//! runs as a service.
use std::io;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

// SYSTEM, Administrators and the owner get full control. Authenticated users get 0x12019b (`PIPE_CLIENT_ACCESS`), read/write without FILE_CREATE_PIPE_INSTANCE, so only the agent adds instances.
const SDDL: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;0x12019b;;;AU)";

/// Claims `name`. Fails when another process already serves it; see [`name_in_use`].
pub fn first_instance(name: &str) -> io::Result<NamedPipeServer> {
    create(name, true, SDDL)
}

/// Adds an instance to a pipe this process already owns.
pub fn next_instance(name: &str) -> io::Result<NamedPipeServer> {
    create(name, false, SDDL)
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
    use lodeline_core::hook_proto::PIPE_CLIENT_ACCESS;
    use std::os::windows::fs::OpenOptionsExt;

    fn unique_name() -> String {
        format!(r"\\.\pipe\lodeline-test-{}", uuid::Uuid::now_v7())
    }

    #[test]
    fn sddl_parses_and_grants_the_hook_access_mask() {
        assert!(SecurityDescriptor::from_sddl(SDDL).is_ok());
        assert!(SDDL.contains(&format!("{PIPE_CLIENT_ACCESS:#x}")));
    }

    #[tokio::test]
    async fn second_first_instance_reports_name_in_use() {
        let name = unique_name();
        let _other = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let err = first_instance(&name).unwrap_err();
        assert!(name_in_use(&err), "{err:?}");
    }

    #[tokio::test]
    async fn client_mask_connects_but_cannot_add_instances() {
        let name = unique_name();
        // Grant every caller the client mask only, as a user other than the owner sees it.
        let _server = create(&name, true, "D:(A;;0x12019b;;;WD)").unwrap();

        let generic_rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap_err();
        assert_eq!(
            generic_rw.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE"
        );

        let added = create(&name, false, "D:(A;;0x12019b;;;WD)").unwrap_err();
        assert_eq!(added.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));

        std::fs::OpenOptions::new()
            .access_mode(PIPE_CLIENT_ACCESS)
            .open(&name)
            .expect("hook access mask connects");
    }
}
