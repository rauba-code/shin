#![deny(warnings)]
extern crate async_channel as ampsc;
extern crate async_oneshot as aoneshot;
extern crate async_process as aprocess;
extern crate async_recursion;
extern crate async_thread as athread;
extern crate env_logger;
extern crate event_listener as aevent;
extern crate futures as ft;
extern crate libc;
extern crate log;
extern crate nix;
extern crate num_derive;
extern crate num_traits;

pub mod errstr {
    pub const FMPSCSEND: &str = "Failed to send MPSC message";
    pub const FRECV: &str = "Failed to receive async message";
    pub const FUTFPARSE: &str = "Failed to parse UTF-8 string";
    pub const FPOISON: &str = "Unexpected poisoning of a channel";
    pub const WPOISON: &str = "The channel is poisoned";
    pub const FRDIALOG : &str = "Failed to receive dialog answer";
    
    pub struct TracerReadyMessage;
    pub type TxTracerReady = aoneshot::Sender<TracerReadyMessage>;
    pub type RxTracerReady = aoneshot::Receiver<TracerReadyMessage>;
    pub enum DialogAnswer {
        Continue,
        StopSubchild,
        KillSubchild,
        Exit
    }
    pub type TxDialog = aoneshot::Sender<DialogAnswer>;
    pub type RxDialog = aoneshot::Receiver<DialogAnswer>;
    
    #[derive(Debug)]
    pub enum TerminationStatus {
        Exited(i32),
        Killed(nix::sys::signal::Signal),
    }
    #[derive(Clone, Debug)]
    pub struct ExecveMessage {
        pub pathname: String,
        pub args: Vec<String>,
        pub envp: Vec<String>,
        pub pid: nix::unistd::Pid,
    }
    pub enum TracerMessage {
        ChildExited(TerminationStatus),
        SubchildSpawning(ExecveMessage, TxDialog),
        //SubchildSpawned(i32),
        //SubchildEnded,
        ShellOutput(i32, Vec<u8>),
    }
    pub enum Message {
        Stdout(Vec<u8>),
        Stderr(Vec<u8>),
        Waiter(nix::unistd::Pid, TracerMessage),
        TracerWait,
    }
    pub type Tx = ampsc::Sender<Message>;
    pub type Rx = ampsc::Receiver<Message>;
}

mod busy_handle;
mod functional;
mod lazy_channel;
mod ptrace_extras;
mod siginfo;
mod tracer;
mod proto_tracer;

fn main() {
    env_logger::init();
    ft::executor::block_on(functional::async_main());
}
