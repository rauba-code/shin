//! POSIX-compliant system calls resolver

//use nix::sys::ptrace;
//use nix::unistd;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::os::raw::*;

#[derive(Clone, Copy, Debug)]
pub struct SigChldInfo {
    pub pid: c_int,
    pub uid: c_uint,
    pub status: c_int,
    pub utime: i64,
    pub stime: i64,
}

#[derive(Clone, Copy, Debug)]
pub enum SigInfoType {
    SigChld(SigChldInfo),
    Other,
}

#[derive(Clone, Copy, Debug)]
pub struct SigInfo {
    pub signo: c_int,
    pub errno: c_int,
    pub code: c_int,
    pub stype: SigInfoType,
}

#[cfg(target_arch = "x86_64")]
#[derive(FromPrimitive, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum Signum {
    // non-POSIX calls are commented out
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    //SIGIOT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    //SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    //SIGWINCH = 28,
    //SIGIO = 29,
    //SIGPWR = 30,
    SIGSYS = 31,
}

/// A safety wrapper around siginfo_t for signals
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64"
))]
pub fn get_signal_info(si: libc::siginfo_t) -> SigInfo {
    SigInfo {
        signo: si.si_signo,
        errno: si.si_errno,
        code: si.si_code,
        stype: match FromPrimitive::from_i32(si.si_signo) {
            Some(Signum::SIGCHLD) => SigInfoType::SigChld(SigChldInfo {
                pid: unsafe { si.si_pid() },
                uid: unsafe { si.si_uid() },
                status: unsafe { si.si_status() },
                utime: unsafe { si.si_utime() },
                stime: unsafe { si.si_stime() },
            }),
            _ => SigInfoType::Other,
        },
    }
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64"
)))]
pub fn get_signal_info(siginfo: libc::siginfo_t) {
    todo!("Unsupported architecture")
}
