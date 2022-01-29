use nix::sys::ptrace;
use nix::unistd;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::os::raw::*;

#[derive(Clone, Copy, Debug)]
pub struct PtraceSyscallInfoEntry {
    pub nr: u64,
    pub args: [u64; 6],
}

#[derive(Clone, Copy, Debug)]
pub struct PtraceSyscallInfoExit {
    pub rval: i64,
    pub is_error: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct PtraceSyscallInfoSeccomp {
    pub nr: u64,
    pub args: [u64; 6],
    pub ret_data: u32,
}

#[repr(C)]
union CPtraceSyscallInfoData {
    entry: PtraceSyscallInfoEntry,
    exit: PtraceSyscallInfoExit,
    seccomp: PtraceSyscallInfoSeccomp,
}

#[repr(C)]
struct CPtraceSyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: CPtraceSyscallInfoData,
}

#[derive(Debug)]
pub enum PtraceSyscallInfoData {
    None,
    Entry(PtraceSyscallInfoEntry),
    Exit(PtraceSyscallInfoExit),
    Seccomp(PtraceSyscallInfoSeccomp),
}

#[derive(Debug)]
pub struct PtraceSyscallInfo {
    pub arch: u32,
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub data: PtraceSyscallInfoData,
}

#[derive(FromPrimitive)]
enum PtraceSyscallInfoType {
    None = 0,
    Entry = 1,
    Exit = 2,
    Seccomp = 3,
}

pub unsafe fn ptrace_get_syscall_info(pid: unistd::Pid) -> PtraceSyscallInfo {
    let sz_cpsci: libc::size_t = std::mem::size_of::<CPtraceSyscallInfo>();
    let sci: *mut CPtraceSyscallInfo = libc::malloc(sz_cpsci) as *mut CPtraceSyscallInfo;
    const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
    if libc::ptrace(
        PTRACE_GET_SYSCALL_INFO,
        libc::pid_t::from(pid),
        sz_cpsci,
        sci,
    ) < 0
    {
        panic!("Ptrace returned 0");
    }
    let op: PtraceSyscallInfoType = FromPrimitive::from_u8((*sci).op).unwrap();
    let data: PtraceSyscallInfoData = match op {
        PtraceSyscallInfoType::None => PtraceSyscallInfoData::None,
        PtraceSyscallInfoType::Entry => PtraceSyscallInfoData::Entry((*sci).data.entry),
        PtraceSyscallInfoType::Exit => PtraceSyscallInfoData::Exit((*sci).data.exit),
        PtraceSyscallInfoType::Seccomp => PtraceSyscallInfoData::Seccomp((*sci).data.seccomp),
    };
    let safe_sci = PtraceSyscallInfo {
        arch: (*sci).arch,
        instruction_pointer: (*sci).instruction_pointer,
        stack_pointer: (*sci).stack_pointer,
        data,
    };
    libc::free(sci as *mut libc::c_void); // free() never fails
    safe_sci
}

pub fn ptrace_get_char_array(
    pid: unistd::Pid,
    addr: *const c_char,
    count: usize,
) -> nix::Result<Vec<u8>> {
    const WORDLEN: usize = 8;
    let mut maddr = addr as *mut c_void;
    let mut left = count;
    let mut vec = Vec::<u8>::with_capacity(count);
    while left > 0 {
        // PTRACE_PEEKTEXT in ptrace(2) is ptrace::read in nix
        let word = ptrace::read(pid, maddr)?;
        let wslice: [u8; WORDLEN] = word.to_ne_bytes();
        let bytes_read = if left > WORDLEN { WORDLEN } else { left };
        vec.extend_from_slice(&wslice[0..bytes_read]);
        // advance by WORDLEN bytes
        maddr = ((maddr as usize) + WORDLEN) as *mut c_void;
        left -= bytes_read;
    }
    Ok(vec)
}

#[allow(warnings)]
pub fn ptrace_get_char_array_nullterm_8(
    pid: unistd::Pid,
    addr: *const c_char
) -> nix::Result<Vec<u8>> {
    const WORDLEN: usize = 8;
    let mut maddr = addr as *mut c_void;
    let mut vec = Vec::<u8>::with_capacity(WORDLEN);
    loop {
        // PTRACE_PEEKTEXT in ptrace(2) is ptrace::read in nix
        let word = ptrace::read(pid, maddr)?;
        let wslice: [u8; WORDLEN] = word.to_ne_bytes();
        let bytes_read : usize = {
            let mut bread = 0;
            for i in wslice {
                if i == 0 {
                    break;
                }
                bread += 1;
            }
            bread
        };
        
        vec.extend_from_slice(&wslice[0..bytes_read]);
        // advance by WORDLEN bytes
        maddr = ((maddr as usize) + WORDLEN) as *mut c_void;
        if bytes_read < WORDLEN {
            break;
        }
    }
    Ok(vec)
}

pub fn ptrace_get_char_array_nullterm_64<T>(
    pid: unistd::Pid,
    addr: *const T
) -> nix::Result<Vec<u64>> {
    const WORDLEN: usize = 8;
    let mut maddr = addr as *mut c_void;
    let mut vec = Vec::<u64>::with_capacity(WORDLEN);
    loop {
        // PTRACE_PEEKTEXT in ptrace(2) is ptrace::read in nix
        let word = ptrace::read(pid, maddr)? as u64;
        let bytes_read : usize = if word == 0 { 0 } else { WORDLEN };
        if bytes_read < WORDLEN {
            break;
        } else {
            vec.push(word);
        }
        // advance by WORDLEN bytes
        maddr = ((maddr as usize) + WORDLEN) as *mut c_void;
    }
    Ok(vec)
}

// This must be identical with /usr/include/linux/ptrace.h
#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum PtraceEvent {
    Fork = 1,
    Vfork = 2,
    Clone = 3,
    Exec = 4,
    VForkDone = 5,
    Exit = 6,
    Seccomp = 7,
    Stop = 128,
}

// This keymap is used for debugging purposes only
pub const _SYSCALL_NAME: [&str; 347] = [
    "read",
    "write",
    "open",
    "close",
    "stat",
    "fstat",
    "lstat",
    "poll",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "ioctl",
    "pread",
    "pwrite",
    "readv",
    "writev",
    "access",
    "pipe",
    "select",
    "sched_yield",
    "mremap",
    "msync",
    "mincore",
    "madvise",
    "shmget",
    "shmat",
    "shmctl",
    "dup",
    "dup",
    "pause",
    "nanosleep",
    "getitimer",
    "alarm",
    "setitimer",
    "getpid",
    "sendfile",
    "socket",
    "connect",
    "accept",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
    "bind",
    "listen",
    "getsockname",
    "getpeername",
    "socketpair",
    "setsockopt",
    "getsockopt",
    "clone",
    "fork",
    "vfork",
    "execve",
    "exit",
    "wait",
    "kill",
    "uname",
    "semget",
    "semop",
    "semctl",
    "shmdt",
    "msgget",
    "msgsnd",
    "msgrcv",
    "msgctl",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "truncate",
    "ftruncate",
    "getdents",
    "getcwd",
    "chdir",
    "fchdir",
    "rename",
    "mkdir",
    "rmdir",
    "creat",
    "link",
    "unlink",
    "symlink",
    "readlink",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "umask",
    "gettimeofday",
    "getrlimit",
    "getrusage",
    "sysinfo",
    "times",
    "ptrace",
    "getuid",
    "syslog",
    "getgid",
    "setuid",
    "setgid",
    "geteuid",
    "getegid",
    "setpgid",
    "getppid",
    "getpgrp",
    "setsid",
    "setreuid",
    "setregid",
    "getgroups",
    "setgroups",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "getpgid",
    "setfsuid",
    "setfsgid",
    "getsid",
    "capget",
    "capset",
    "rt_sigpending",
    "rt_sigtimedwait",
    "rt_sigqueueinfo",
    "rt_sigsuspend",
    "sigaltstack",
    "utime",
    "mknod",
    "uselib",
    "personality",
    "ustat",
    "statfs",
    "fstatfs",
    "sysfs",
    "getpriority",
    "setpriority",
    "sched_setparam",
    "sched_getparam",
    "sched_setscheduler",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "sched_rr_get_interval",
    "mlock",
    "munlock",
    "mlockall",
    "munlockall",
    "vhangup",
    "modify_ldt",
    "pivot_root",
    "_sysctl",
    "prctl",
    "arch_prctl",
    "adjtimex",
    "setrlimit",
    "chroot",
    "sync",
    "acct",
    "settimeofday",
    "mount",
    "umount",
    "swapon",
    "swapoff",
    "reboot",
    "sethostname",
    "setdomainname",
    "iopl",
    "ioperm",
    "create_module",
    "init_module",
    "delete_module",
    "get_kernel_syms",
    "query_module",
    "quotactl",
    "nfsservctl",
    "getpmsg",
    "putpmsg",
    "afs_syscall",
    "tuxcall",
    "security",
    "gettid",
    "readahead",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "getxattr",
    "lgetxattr",
    "fgetxattr",
    "listxattr",
    "llistxattr",
    "flistxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "tkill",
    "time",
    "futex",
    "sched_setaffinity",
    "sched_getaffinity",
    "set_thread_area",
    "io_setup",
    "io_destroy",
    "io_getevents",
    "io_submit",
    "io_cancel",
    "get_thread_area",
    "lookup_dcookie",
    "epoll_create",
    "epoll_ctl_old",
    "epoll_wait_old",
    "remap_file_pages",
    "getdents",
    "set_tid_address",
    "restart_syscall",
    "semtimedop",
    "fadvise",
    "timer_create",
    "timer_settime",
    "timer_gettime",
    "timer_getoverrun",
    "timer_delete",
    "clock_settime",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "exit_group",
    "epoll_wait",
    "epoll_ctl",
    "tgkill",
    "utimes",
    "vserver",
    "mbind",
    "set_mempolicy",
    "get_mempolicy",
    "mq_open",
    "mq_unlink",
    "mq_timedsend",
    "mq_timedreceive",
    "mq_notify",
    "mq_getsetattr",
    "kexec_load",
    "waitid",
    "add_key",
    "request_key",
    "keyctl",
    "ioprio_set",
    "ioprio_get",
    "inotify_init",
    "inotify_add_watch",
    "inotify_rm_watch",
    "migrate_pages",
    "openat",
    "mkdirat",
    "mknodat",
    "fchownat",
    "futimesat",
    "newfstatat",
    "unlinkat",
    "renameat",
    "linkat",
    "symlinkat",
    "readlinkat",
    "fchmodat",
    "faccessat",
    "pselect",
    "ppoll",
    "unshare",
    "set_robust_list",
    "get_robust_list",
    "splice",
    "tee",
    "sync_file_range",
    "vmsplice",
    "move_pages",
    "utimensat",
    "epoll_pwait",
    "signalfd",
    "timerfd_create",
    "eventfd",
    "fallocate",
    "timerfd_settime",
    "timerfd_gettime",
    "accept",
    "signalfd",
    "eventfd",
    "epoll_create",
    "dup",
    "pipe",
    "inotify_init",
    "preadv",
    "pwritev",
    "rt_tgsigqueueinfo",
    "perf_event_open",
    "recvmmsg",
    "fanotify_init",
    "fanotify_mark",
    "prlimit",
    "name_to_handle_at",
    "open_by_handle_at",
    "clock_adjtime",
    "syncfs",
    "sendmmsg",
    "setns",
    "getcpu",
    "process_vm_readv",
    "process_vm_writev",
    "kcmp",
    "finit_module",
    "sched_setattr",
    "sched_getattr",
    "renameat",
    "seccomp",
    "getrandom",
    "memfd_create",
    "kexec_file_load",
    "bpf",
    "execveat",
    "userfaultfd",
    "membarrier",
    "mlock",
    "copy_file_range",
    "preadv",
    "pwritev",
    "pkey_mprotect",
    "pkey_alloc",
    "pkey_free",
    "statx",
    "io_pgetevents",
    "rseq",
    "pidfd_send_signal",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "pidfd_open",
    "clone",
];
