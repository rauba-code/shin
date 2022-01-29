use crate::errstr::*;
use crate::lazy_channel::*;
use crate::ptrace_extras::*;
use crate::siginfo::*;
use async_recursion::async_recursion;
use libc::siginfo_t;
use nix::unistd::Pid;
use nix::{sys, unistd};
use std::os::raw::*;

use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal;
use nix::sys::signal::Signal;
use sys::wait;
const FWAITPID: &str = "Failed to wait on child process";
const FPTSYSCALL: &str = "Failed to continue execution until next syscall";
const FPMEMREF: &str = "Failed to get memory reference of a child via ptrace";
const FKILL: &str = "Failed to kill a subchild";

#[derive(Clone, Copy, Debug)]
pub struct WriteSyscall {
    fd: i32,
    buffer: *const c_char,
    count: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecveSyscall {
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
}

#[derive(Clone, Copy, Debug)]
pub enum Syscall {
    Read,
    Write(WriteSyscall),
    Clone,
    Execve(ExecveSyscall),
    Other(u64, [u64; 6]),
}

impl ExecveSyscall {
    pub fn to_execve_message(self, pid: Pid) -> ExecveMessage {
        let pathname = ptrace_get_char_array_nullterm_8(pid, self.pathname).expect(FPMEMREF);
        let args = resolve_char_arrays(pid, self.argv);
        let envp = resolve_char_arrays(pid, self.envp);
        ExecveMessage {
            pathname: String::from_utf8(pathname).expect(FUTFPARSE),
            args: args
                .iter()
                .map(|x| String::from_utf8(x.to_vec()).expect(FUTFPARSE))
                .collect::<Vec<String>>(),
            envp: envp
                .iter()
                .map(|x| String::from_utf8(x.to_vec()).expect(FUTFPARSE))
                .collect::<Vec<String>>(),
            pid
        }
    }
}

fn resolve_syscall(entry: PtraceSyscallInfoEntry) -> Syscall {
    match entry.nr {
        0 => Syscall::Read,
        1 => Syscall::Write(WriteSyscall {
            fd: entry.args[0] as i32,
            buffer: entry.args[1] as *const c_char,
            count: entry.args[2] as usize,
        }),
        56 => Syscall::Clone,
        59 => Syscall::Execve(ExecveSyscall {
            pathname: entry.args[0] as *const c_char,
            argv: entry.args[1] as *const *const c_char,
            envp: entry.args[2] as *const *const c_char,
        }),
        _ => Syscall::Other(entry.nr, entry.args),
    }
}

fn resolve_char_arrays(pid: Pid, p: *const *const c_char) -> Vec<Vec<u8>> {
    ptrace_get_char_array_nullterm_64(pid, p as *const ())
        .expect(FPMEMREF)
        .iter()
        .map(|x| ptrace_get_char_array_nullterm_8(pid, *x as *const c_char).expect(FPMEMREF))
        .collect()
}

enum TraceRetv {
    None,
    Syscall(Syscall),
    Exit,
}

async fn ptrace_syscall_resolve<'a, F>(
    pid: Pid,
    last_syscall: &Option<Syscall>,
    send: &F,
    tx_stdout_busy: &TxLazyChannel<Vec<u8>>,
    tx_stderr_busy: &TxLazyChannel<Vec<u8>>,
) -> TraceRetv
where
    F: Fn(TracerMessage) -> ampsc::Send<'a, Message> + std::marker::Send + std::marker::Sync,
{
    let sci = unsafe { ptrace_get_syscall_info(pid) };
    //println!("{:#?}", sci);
    match sci.data {
        PtraceSyscallInfoData::None => {
            println!("-- signal --");
            todo!("signal interrupt");
        }
        PtraceSyscallInfoData::Entry(entry) => {
            let syscall = resolve_syscall(entry);
            match syscall {
                Syscall::Write(write) => match write.fd {
                    1 => tx_stdout_busy.busy().expect("business error"),
                    2 => tx_stderr_busy.busy().expect("business error"),
                    _ => (),
                },
                Syscall::Execve(execve) => {
                    let (txd, rxd) = aoneshot::oneshot();
                    send(TracerMessage::SubchildSpawning(
                        execve.to_execve_message(pid),
                        txd,
                    )).await.expect(FMPSCSEND);
                    match rxd.await.expect(FRDIALOG) {
                        DialogAnswer::Continue => {
                            ptrace::detach(pid, None).expect("Failed to detach from a process")
                        }
                        DialogAnswer::StopSubchild => {
                            signal::kill(pid, signal::SIGTERM).expect(FKILL)
                        }
                        DialogAnswer::KillSubchild => {
                            signal::kill(pid, signal::SIGKILL).expect(FKILL)
                        }
                        DialogAnswer::Exit => (),
                    }
                    return TraceRetv::Exit;
                }
                _ => (),
            }
            return TraceRetv::Syscall(syscall);
        }
        PtraceSyscallInfoData::Exit(exit) => match last_syscall {
            Some(Syscall::Clone) => {
                //let tpid = unistd::Pid::from_raw(exit.rval as i32);
                println!("-- (");
                let (tx_sc_ready, _rx_sc_ready) = aoneshot::oneshot();
                tracer_main(
                    exit.rval as u32,
                    send,
                    tx_sc_ready,
                    tx_stdout_busy,
                    tx_stderr_busy,
                )
                .await;
                println!(") --");
            }
            Some(Syscall::Write(write)) => {
                let text = ptrace_get_char_array(pid, write.buffer, exit.rval as usize)
                    .expect("Failed to get text with ptrace");
                let text2 = text.clone();
                send(TracerMessage::ShellOutput(write.fd, text))
                    .await
                    .expect(FMPSCSEND);
                match write.fd {
                    1 => tx_stdout_busy.done(text2).expect("business error"),
                    2 => tx_stderr_busy.done(text2).expect("business error"),
                    _ => (),
                }
            }
            _ => (),
        },
        _ => todo!("seccomp"),
    };
    TraceRetv::None
}

async fn pid_resolve<'a, F>(
    pid: Pid,
    last_syscall: &Option<Syscall>,
    send: &F,
    tx_stdout_busy: &TxLazyChannel<Vec<u8>>,
    tx_stderr_busy: &TxLazyChannel<Vec<u8>>,
) -> TraceRetv
where
    F: Fn(TracerMessage) -> ampsc::Send<'a, Message> + std::marker::Send + std::marker::Sync,
{
    let w = wait::waitpid(pid, None).expect(FWAITPID);
    match w {
        wait::WaitStatus::Exited(_, retv) => {
            send(TracerMessage::ChildExited(TerminationStatus::Exited(retv)))
                .await
                .expect(FMPSCSEND);
            TraceRetv::Exit
        }
        wait::WaitStatus::Signaled(_, signal, _) => {
            send(TracerMessage::ChildExited(TerminationStatus::Killed(
                signal,
            )))
            .await
            .expect(FMPSCSEND);
            // TODO: not all signals are terminating
            TraceRetv::Exit
        }
        wait::WaitStatus::StillAlive => TraceRetv::None,
        wait::WaitStatus::PtraceSyscall(ppid) => {
            assert!(pid == ppid);
            ptrace_syscall_resolve(ppid, last_syscall, send, tx_stdout_busy, tx_stderr_busy).await
        }
        wait::WaitStatus::Stopped(spid, sig) => {
            assert!(spid == pid);
            match sig {
                Signal::SIGCHLD => {
                    let si: siginfo_t =
                        ptrace::getsiginfo(spid).expect("Failed to get signal info with ptrace");
                    let siginfo: SigInfo = get_signal_info(si);
                    println!("pid: {}", spid);
                    println!("Stopped; Got {:?}", siginfo);
                    TraceRetv::None
                }
                _ => todo!("Other signal: {:?}", sig),
            }
        }
        _ => {
            todo!("Other waitpid value: {:?}", w)
        }
    }
}

#[allow(dead_code)]
#[async_recursion(?Send)]
pub async fn tracer_main<'a, F>(
    raw_cpid: u32,
    send: &F,
    mut tx_tracer_ready: TxTracerReady,
    tx_stdout_busy: &TxLazyChannel<Vec<u8>>,
    tx_stderr_busy: &TxLazyChannel<Vec<u8>>,
) where
    F: Fn(TracerMessage) -> ampsc::Send<'a, Message> + std::marker::Send + std::marker::Sync,
{
    let pid = unistd::Pid::from_raw(raw_cpid as i32);
    ptrace::attach(pid).expect("Failed to attach ptrace on child");
    let _ = wait::waitpid(pid, None).expect(FWAITPID);
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_EXITKILL
            //| Options::PTRACE_O_TRACECLONE
            //| Options::PTRACE_O_TRACEEXEC
            //| Options::PTRACE_O_TRACEEXIT
            //| Options::PTRACE_O_TRACEFORK
            //| Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACESYSGOOD,
    )
    .expect("Failed to set ptrace options on child");
    tx_tracer_ready.send(TracerReadyMessage).expect(FMPSCSEND);
    let mut last_syscall: Option<Syscall> = None;
    loop {
        ptrace::syscall(pid, None).expect(FPTSYSCALL);
        match pid_resolve(pid, &last_syscall, send, tx_stdout_busy, tx_stderr_busy).await {
            TraceRetv::None => (),
            TraceRetv::Syscall(new_syscall) => last_syscall = Some(new_syscall),
            TraceRetv::Exit => break,
        }
    }
}
