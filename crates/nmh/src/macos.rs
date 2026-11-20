use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::base::CFTypeRef;
use security_framework_sys::code_signing::{
    SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeCopyPath, SecCodeRef,
    SecRequirementCreateWithString, SecRequirementRef, SecStaticCodeCheckValidity,
    SecStaticCodeCreateWithPath, SecStaticCodeRef, kSecGuestAttributeAudit, kSecGuestAttributePid,
};

use crate::peer::{CodeTarget, CodeVerifier, PeerError, Requirement, VerifiedCode};

const ERR_SEC_CS_UNSIGNED: i32 = -67_062;
const ERR_SEC_CS_REQ_FAILED: i32 = -67_050;
const ERR_SEC_CS_NO_SUCH_CODE: i32 = -67_065;

#[derive(Clone, Copy, Debug)]
pub struct SystemVerifier;

impl CodeVerifier for SystemVerifier {
    fn peer_of(&self, stream: &UnixStream) -> Result<CodeTarget, PeerError> {
        let fd = stream.as_raw_fd();
        if peer_uid(fd)? != effective_uid() {
            return Err(PeerError::OtherUser);
        }
        peer_token(fd).map(CodeTarget::AuditToken)
    }

    fn parent(&self) -> Result<CodeTarget, PeerError> {
        let pid = parent_pid();
        if pid <= 1 {
            return Err(PeerError::Unidentified);
        }
        Ok(CodeTarget::Pid(pid))
    }

    fn verify(
        &self,
        target: &CodeTarget,
        requirement: &Requirement,
    ) -> Result<VerifiedCode, PeerError> {
        let requirement = compile(requirement)?;
        match target {
            CodeTarget::Path(path) => check_static(path, &requirement),
            CodeTarget::Pid(pid) => {
                let attribute = CFNumber::from(*pid);
                check_guest(pid_key(), attribute.as_CFType(), &requirement)
            }
            CodeTarget::AuditToken(token) => check_guest(
                audit_key(),
                CFData::from_buffer(token).as_CFType(),
                &requirement,
            ),
        }
    }
}

fn status(code: i32) -> PeerError {
    match code {
        ERR_SEC_CS_UNSIGNED | ERR_SEC_CS_REQ_FAILED => PeerError::Mismatch,
        ERR_SEC_CS_NO_SUCH_CODE => PeerError::Unidentified,
        other => PeerError::Check(other),
    }
}

fn check_guest(
    key: CFString,
    value: CFType,
    requirement: &CFType,
) -> Result<VerifiedCode, PeerError> {
    let attributes = CFDictionary::from_CFType_pairs(&[(key, value)]);
    let code = copy_guest(&attributes)?;
    check_code(&code, requirement)?;
    Ok(VerifiedCode {
        path: code_path(&code)?,
    })
}

fn check_static(path: &Path, requirement: &CFType) -> Result<VerifiedCode, PeerError> {
    let url = CFURL::from_path(path, false).ok_or(PeerError::Unidentified)?;
    let code = copy_static(&url)?;
    check_static_code(&code, requirement)?;
    Ok(VerifiedCode {
        path: path.to_path_buf(),
    })
}

#[expect(unsafe_code, reason = "reads a CoreFoundation constant string")]
fn pid_key() -> CFString {
    // SAFETY: an immutable global initialised by the Security framework before main; the get
    // rule retains it.
    unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) }
}

#[expect(unsafe_code, reason = "reads a CoreFoundation constant string")]
fn audit_key() -> CFString {
    // SAFETY: an immutable global initialised by the Security framework before main; the get
    // rule retains it.
    unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) }
}

#[expect(unsafe_code, reason = "calls SecRequirementCreateWithString")]
fn compile(requirement: &Requirement) -> Result<CFType, PeerError> {
    let text = CFString::new(requirement.as_str());
    let mut out: SecRequirementRef = ptr::null_mut();
    // SAFETY: `text` is a live CFString and `out` is a valid out pointer for the call.
    let code =
        unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &raw mut out) };
    if code != 0 || out.is_null() {
        return Err(PeerError::Requirement);
    }
    // SAFETY: a Create function returned a +1 reference this value now owns.
    Ok(unsafe { CFType::wrap_under_create_rule(out.cast_const() as CFTypeRef) })
}

#[expect(unsafe_code, reason = "calls SecCodeCopyGuestWithAttributes")]
fn copy_guest(attributes: &CFDictionary<CFString, CFType>) -> Result<CFType, PeerError> {
    let mut code: SecCodeRef = ptr::null_mut();
    // SAFETY: a null host means the system host, `attributes` is live and `code` is a valid out
    // pointer.
    let result = unsafe {
        SecCodeCopyGuestWithAttributes(
            ptr::null_mut(),
            attributes.as_concrete_TypeRef(),
            0,
            &raw mut code,
        )
    };
    if result != 0 || code.is_null() {
        return Err(status(result));
    }
    // SAFETY: a Copy function returned a +1 reference this value now owns.
    Ok(unsafe { CFType::wrap_under_create_rule(code.cast_const() as CFTypeRef) })
}

#[expect(unsafe_code, reason = "calls SecCodeCheckValidity")]
fn check_code(code: &CFType, requirement: &CFType) -> Result<(), PeerError> {
    // SAFETY: both references are live CoreFoundation objects of the types the function names.
    let result = unsafe {
        SecCodeCheckValidity(
            code.as_CFTypeRef() as SecCodeRef,
            0,
            requirement.as_CFTypeRef() as SecRequirementRef,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(status(result))
    }
}

#[expect(unsafe_code, reason = "calls SecCodeCopyPath")]
fn code_path(code: &CFType) -> Result<std::path::PathBuf, PeerError> {
    let mut url: core_foundation_sys::url::CFURLRef = ptr::null();
    // SAFETY: `code` is a live SecCode, a SecCode is a valid SecStaticCode, and `url` is a valid
    // out pointer.
    let result =
        unsafe { SecCodeCopyPath(code.as_CFTypeRef() as SecStaticCodeRef, 0, &raw mut url) };
    if result != 0 || url.is_null() {
        return Err(status(result));
    }
    // SAFETY: a Copy function returned a +1 reference this value now owns.
    let url = unsafe { CFURL::wrap_under_create_rule(url) };
    url.to_path().ok_or(PeerError::Unidentified)
}

#[expect(unsafe_code, reason = "calls SecStaticCodeCreateWithPath")]
fn copy_static(url: &CFURL) -> Result<CFType, PeerError> {
    let mut code: SecStaticCodeRef = ptr::null_mut();
    // SAFETY: `url` is a live CFURL and `code` is a valid out pointer.
    let result =
        unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &raw mut code) };
    if result != 0 || code.is_null() {
        return Err(status(result));
    }
    // SAFETY: a Create function returned a +1 reference this value now owns.
    Ok(unsafe { CFType::wrap_under_create_rule(code.cast_const() as CFTypeRef) })
}

#[expect(unsafe_code, reason = "calls SecStaticCodeCheckValidity")]
fn check_static_code(code: &CFType, requirement: &CFType) -> Result<(), PeerError> {
    // SAFETY: both references are live CoreFoundation objects of the types the function names.
    let result = unsafe {
        SecStaticCodeCheckValidity(
            code.as_CFTypeRef() as SecStaticCodeRef,
            0,
            requirement.as_CFTypeRef() as SecRequirementRef,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(status(result))
    }
}

#[expect(unsafe_code, reason = "calls getsockopt LOCAL_PEERTOKEN")]
fn peer_token(fd: libc::c_int) -> Result<[u8; 32], PeerError> {
    let mut token = [0_u8; 32];
    let mut len = libc::socklen_t::try_from(token.len()).map_err(|_| PeerError::Unidentified)?;
    // SAFETY: `fd` is a live socket, `token` is a writable buffer of `len` bytes.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if result != 0 || usize::try_from(len).ok() != Some(token.len()) {
        return Err(PeerError::Unidentified);
    }
    Ok(token)
}

#[expect(unsafe_code, reason = "calls getpeereid")]
fn peer_uid(fd: libc::c_int) -> Result<u32, PeerError> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a live socket and both out pointers are valid.
    let result = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
    if result != 0 {
        return Err(PeerError::Unidentified);
    }
    Ok(uid)
}

#[expect(unsafe_code, reason = "calls geteuid")]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

#[expect(unsafe_code, reason = "calls getppid")]
fn parent_pid() -> i32 {
    // SAFETY: getppid takes no arguments and cannot fail.
    unsafe { libc::getppid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn apple_signed_system_binary_satisfies_anchor_apple() {
        let target = CodeTarget::Path("/usr/bin/true".into());
        let verified = SystemVerifier
            .verify(&target, &Requirement::apple_system())
            .unwrap();
        assert_eq!(verified.path, std::path::PathBuf::from("/usr/bin/true"));
    }

    #[test]
    fn a_system_binary_does_not_satisfy_a_third_party_team() {
        let target = CodeTarget::Path("/usr/bin/true".into());
        for rule in &crate::peer::BROWSERS {
            let result = SystemVerifier.verify(&target, &rule.requirement().unwrap());
            assert_eq!(result, Err(PeerError::Mismatch), "{:?}", rule.browser);
        }
        assert_eq!(
            crate::peer::identify_browser(&SystemVerifier, &target),
            Err(PeerError::Mismatch)
        );
    }

    #[test]
    fn a_running_apple_process_is_checked_by_pid() {
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let verified = SystemVerifier
            .verify(&CodeTarget::Pid(pid), &Requirement::apple_system())
            .unwrap();
        assert!(verified.path.ends_with("cat"));
        let foreign = crate::peer::BROWSERS[0].requirement().unwrap();
        assert_eq!(
            SystemVerifier.verify(&CodeTarget::Pid(pid), &foreign),
            Err(PeerError::Mismatch)
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn the_test_binary_is_not_apple_signed_by_a_team() {
        let me = CodeTarget::Pid(i32::try_from(std::process::id()).unwrap());
        let host = Requirement::signed_by(
            &["kr.jmo.hasp.nmh"],
            "ABCDE12345",
            crate::peer::Signing::DeveloperId,
        )
        .unwrap();
        assert!(matches!(
            SystemVerifier.verify(&me, &host),
            Err(PeerError::Mismatch | PeerError::Check(_))
        ));
    }

    #[test]
    fn identifies_the_peer_of_a_socket_pair_as_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let target = SystemVerifier.peer_of(&a).unwrap();
        assert!(matches!(target, CodeTarget::AuditToken(_)));
    }

    #[test]
    fn every_shipped_requirement_compiles() {
        for rule in &crate::peer::BROWSERS {
            compile(&rule.requirement().unwrap()).unwrap();
        }
        let host = Requirement::signed_by(
            &["kr.jmo.hasp.nmh"],
            "ABCDE12345",
            crate::peer::Signing::AnyTeamCertificate,
        )
        .unwrap();
        compile(&host).unwrap();
    }
}
