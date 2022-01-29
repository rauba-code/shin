use crate::errstr::*;
use crate::lazy_channel::*;

use ft::future::{AbortHandle, Abortable, Aborted};
use ft::{AsyncReadExt, AsyncWriteExt, FutureExt};
use nix::unistd::Pid;
use std::collections::VecDeque;
use std::io;

use std::vec::Vec;

async fn child_stdin_sender(cin: aprocess::ChildStdin, rx_tracer_ready: RxTracerReady) {
    rx_tracer_ready
        .await
        .expect("Failed to await on TracerReady receiver");
    let mut acin = ft::io::BufWriter::new(cin);
    acin.write_all(
        b"text='hello' >file\n
        echo $text\n
        (sleep 5;echo $text)&\n
        envdump\n
        neofetch --stdout\n
        exit\n",
    )
    .await
    .expect("Failed to send input to child");
    acin.flush().await.expect("Failed to flush stdin");
}

async fn child_stdio_receiver<'a, F, G>(
    send: F,
    mut cout: G,
    mut rx_io_busy: RxLazyChannel<Vec<u8>>,
) where
    F: Fn(Vec<u8>) -> ampsc::Send<'a, Message>,
    G: AsyncReadExt + std::marker::Unpin,
{
    let mut msg_filter: MsgFilterQueue = MsgFilterQueue::new();
    const BUFLEN: usize = 1024;
    let mut buf = [0_u8; BUFLEN];
    loop {
        match cout.read_exact(&mut buf[0..1]).await {
            Ok(()) => (),
            Err(e) => match e.kind() {
                io::ErrorKind::UnexpectedEof => break,
                _ => panic!("Failed to listen: {}", e),
            },
        };
        let sz = if let Some(rsz) = cout.read(&mut buf[1..]).fuse().now_or_never() {
            match rsz {
                Ok(ret) => ret,
                Err(e) => match e.kind() {
                    io::ErrorKind::UnexpectedEof => break,
                    _ => panic!("Failed to listen: {}", e),
                },
            }
        } else {
            0
        } + 1;
        for filtmsg in rx_io_busy.wait().await {
            msg_filter.add(filtmsg)
        }
        if msg_filter.filter(&buf[0..sz]) {
            send(buf[0..sz].to_vec()).await.expect(FMPSCSEND);
        }
    }
    println!("Stdio receiver got EOF. Ending"); // TODO: remove this line
}

/// Waits for tracer to end.
/// Rationale: the tracer can panic (or get externally killed).
/// If the tracer panics (or gets killed), it would not report the dispatcher
/// about its end, so this handle reports the dispatcher to end all the jobs.
/// TODO: make tracer an async fn/green thread and get rid of this
async fn tracer_wait<'a, F>(send: F, join_handle: athread::JoinHandle<()>)
where
    F: Fn() -> ampsc::Send<'a, Message>,
{
    let _ = join_handle.join().await;
    send().await.expect(FMPSCSEND);
}

async fn tracer_wait_wrapper(tx: Tx, join_handle: athread::JoinHandle<()>) {
    let tx2 = tx.clone();
    tracer_wait(|| tx2.send(Message::TracerWait), join_handle).await
}

async fn child_stdout_receiver(
    tx: Tx,
    cout: aprocess::ChildStdout,
    rx_io_busy: RxLazyChannel<Vec<u8>>,
) {
    // these FP closures allow us to distinguish message types
    // and get rid of typos
    child_stdio_receiver(|a: Vec<u8>| tx.send(Message::Stdout(a)), cout, rx_io_busy).await
}

async fn child_stderr_receiver(
    tx: Tx,
    cout: aprocess::ChildStderr,
    rx_io_busy: RxLazyChannel<Vec<u8>>,
) {
    child_stdio_receiver(|a: Vec<u8>| tx.send(Message::Stderr(a)), cout, rx_io_busy).await
}

pub struct MsgFilterQueue {
    queue: VecDeque<Vec<u8>>,
}

impl MsgFilterQueue {
    pub fn new() -> MsgFilterQueue {
        MsgFilterQueue {
            queue: VecDeque::<Vec<u8>>::new(),
        }
    }
    pub fn add(&mut self, msg: Vec<u8>) {
        self.queue.push_back(msg);
    }
    pub fn filter(&mut self, msg: &'_ [u8]) -> bool {
        let n = msg.len();
        let p = match self.try_fitting(n) {
            Some(val) => val,
            None => return true,
        };
        let filtmsg: Vec<u8> = self.queue.range(0..=p).fold(
            Vec::with_capacity(n),
            |mut base: Vec<u8>, item: &Vec<u8>| {
                base.extend_from_slice(item);
                base
            },
        );
        if msg == filtmsg {
            self.queue = self.queue.split_off(p + 1);
            false
        } else {
            true
        }
    }
    fn try_fitting(&mut self, n: usize) -> Option<usize> {
        use std::cmp::Ordering;
        let mut total: usize = 0;
        for (i, item) in self.queue.iter().enumerate() {
            total += item.len();
            match total.cmp(&n) {
                Ordering::Greater => return None,
                Ordering::Equal => return Some(i),
                Ordering::Less => (),
            }
        }
        None
    }
}

// TODO: refactor dispatcher to a separate client.
async fn message_dispatcher(rx: Rx, abort_handles: Vec<AbortHandle>) {
    pub const FRLINE: &str = "Client: Failed to read input line";
    pub const FSDIALOG: &str = "Client: Failed to send dialog answer";
    let mut skipmsg_stdout = VecDeque::<Vec<u8>>::new();
    let mut skipmsg_stderr = VecDeque::<Vec<u8>>::new();
    let stdin = io::stdin();
    let mut mainpid: Option<Pid> = None;
    loop {
        let _ = match rx.recv().await {
            Ok(msg) => match msg {
                Message::Stdout(out) => {
                    println!("{:?}", String::from_utf8(out).expect(FUTFPARSE))
                }
                Message::Stderr(out) => {
                    println!("E{:?}", String::from_utf8(out).expect(FUTFPARSE))
                }
                Message::Waiter(wpid, wmsg) => {
                    mainpid = if mainpid == None { Some(wpid) } else { None };
                    match wmsg {
                        TracerMessage::ChildExited(ev) => {
                            if mainpid == Some(wpid) {
                                println!("Shell exited with status {:?}", ev);
                                break;
                            } else {
                                println!("Subchild {} exited", wpid);
                            }
                        }
                        TracerMessage::SubchildSpawning(execve, mut ans) => {
                            println!(
                                "Spawned {:?} {:?} pid: {}",
                                execve.pathname, execve.args, execve.pid
                            );
                            let line: &mut String = &mut String::new();
                            stdin.read_line(line).expect(FRLINE);
                            ans.send(DialogAnswer::Continue).expect(FSDIALOG);
                        }
                        TracerMessage::ShellOutput(fd, charr) => {
                            let charr2 = charr.clone();
                            let text = String::from_utf8(charr).expect(FUTFPARSE);
                            match fd {
                                1 => {
                                    skipmsg_stdout.push_back(charr2);
                                    println!("Shell: {:?}", text)
                                }
                                2 => {
                                    skipmsg_stderr.push_back(charr2);
                                    println!("Shell: E{:?}", text)
                                }
                                _ => println!("Shell (fd: {}): {:?}", fd, text),
                            }
                        }
                    }
                }
                Message::TracerWait => {
                    eprintln!("Tracer panicked. Ending");
                    break;
                }
            },
            Err(e) => {
                println!("DISPATCHER: Got {:?}. Ending", e);
                break;
            }
        };
    }
    for handle in abort_handles {
        handle.abort();
    }
}

use crate::proto_tracer::tracer_main;

pub async fn async_main() {
    let (tx, rx) = ampsc::unbounded();
    let shpath = "/bin/dash";
    let (tx_stdout_busy, rx_stdout_busy) = lazy_channel();
    let (tx_stderr_busy, rx_stderr_busy) = lazy_channel();
    let mut child = aprocess::Command::new(shpath)
        //.args(["-o", "strace.log", "/bin/sh"])
        .stdin(aprocess::Stdio::piped())
        .stdout(aprocess::Stdio::piped())
        .stderr(aprocess::Stdio::piped())
        .spawn()
        .expect("Failed to spawn child process (shell)");
    let (tx_tracer_ready, rx_tracer_ready) = aoneshot::oneshot();
    let ftrace = {
        let tx1 = tx.clone();
        let cpid = child.id();
        let block = move || {
            let send = |pid: nix::unistd::Pid, a: TracerMessage| tx1.send(Message::Waiter(pid, a));
            let fftrace = tracer_main(
                cpid,
                &send,
                tx_tracer_ready,
                &tx_stdout_busy,
                &tx_stderr_busy,
            );
            ft::executor::block_on(fftrace)
        };
        tracer_wait_wrapper(
            tx.clone(),
            athread::Builder::new()
                .name("tracer".to_string())
                .spawn(block)
                .expect("Failed to create a thread"),
        )
    };
    // repetitive code
    let mut handles = Vec::<AbortHandle>::new();
    let (ah, ar) = AbortHandle::new_pair();
    let fin = Abortable::new(
        {
            let cin = child.stdin.take().expect("Failed to take ChildStdin");
            child_stdin_sender(cin, rx_tracer_ready)
        },
        ar,
    );
    handles.push(ah);
    let (ah, ar) = AbortHandle::new_pair();
    let fout = Abortable::new(
        {
            let cout = child.stdout.take().expect("Failed to take ChildStdout");
            child_stdout_receiver(tx.clone(), cout, rx_stdout_busy)
        },
        ar,
    );
    handles.push(ah);
    let (ah, ar) = AbortHandle::new_pair();
    let ferr = Abortable::new(
        {
            let cerr = child.stderr.take().expect("Failed to take ChildStderr");
            child_stderr_receiver(tx.clone(), cerr, rx_stderr_busy)
        },
        ar,
    );
    handles.push(ah);
    let fdispatch = message_dispatcher(rx, handles);
    let (r0, r1, r2, _, _) = ft::join!(fin, fout, ferr, ftrace, fdispatch);
    let r: [std::result::Result<(), Aborted>; 3] = [r0, r1, r2];
    println!("{:?}", r);
}
