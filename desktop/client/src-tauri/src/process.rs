use crate::connection::ConnectionSnapshot;
use crate::stats::{StatsSampler, StatsView};
use crate::telemetry::{classify_line, TelemetryEvent};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub stats_path: Option<PathBuf>,
}

impl CommandSpec {
    pub fn new<P, I, S>(program: P, args: I) -> Self
    where
        P: Into<PathBuf>,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            stats_path: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub success: bool,
    pub reason: ExitReason,
    pub timed_out: bool,
    pub recovery_pending: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ExitReason {
    Natural,
    Graceful,
    ForcedKill,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "lowercase")]
pub enum ProcessEvent {
    Telemetry(TelemetryEvent),
    Stats(StatsView),
    Exited(ExitInfo),
    State(ConnectionSnapshot),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessMessage {
    pub session_id: u64,
    #[serde(flatten)]
    pub event: ProcessEvent,
    pub connection: ConnectionSnapshot,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("ppp 进程已在运行中")]
    AlreadyRunning,
    #[error("ppp 网络恢复仍待处理")]
    /// A future recovery worker must clear the persisted network state before
    /// another session is allowed to start.
    RecoveryPending,
    #[error("无法启动 ppp: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("网络恢复执行器启动失败: {0}")]
    RecoverySpawn(std::io::Error),
    #[error("网络恢复执行器超时")]
    RecoveryTimeout,
    #[error("停止 ppp 失败: {0}")]
    Stop(std::io::Error),
}

type Emitter = Arc<dyn Fn(ProcessMessage) + Send + Sync + 'static>;
type EventSink = Arc<dyn Fn(ProcessEvent) + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Default)]
struct StopContext {
    requested: bool,
    forced: bool,
    timed_out: bool,
    recovery_pending: bool,
}

/// Clones share the same child; `stop` can then run without holding the
/// caller's lock on the manager.
#[derive(Clone)]
pub struct ProcessManager {
    child: Arc<Mutex<Option<Child>>>,
    emit: Emitter,
    snapshot: Arc<Mutex<ConnectionSnapshot>>,
    stop_context: Arc<Mutex<StopContext>>,
    /// Pid whose monitor has taken it from the slot but not yet finished
    /// emitting the final stats and Exited event.
    exiting: Arc<(Mutex<Option<u32>>, Condvar)>,
}

impl ProcessManager {
    pub fn new<F>(emit: F) -> Self
    where
        F: Fn(ProcessMessage) + Send + Sync + 'static,
    {
        Self {
            child: Arc::new(Mutex::new(None)),
            emit: Arc::new(emit),
            snapshot: Arc::new(Mutex::new(ConnectionSnapshot::default())),
            stop_context: Arc::new(Mutex::new(StopContext::default())),
            exiting: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }

    pub fn is_running(&self) -> bool {
        self.child.lock().expect("process lock poisoned").is_some()
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        self.snapshot
            .lock()
            .expect("snapshot lock poisoned")
            .clone()
    }

    /// Restores the durable desktop-side gate after a previous forced stop.
    /// This does not claim that the OS network state is clean; only a verified
    /// recovery path may clear the flag.
    pub fn mark_recovery_pending(&mut self) {
        let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
        snapshot.status = "recovery_pending".into();
        snapshot.phase = "recovery_pending".into();
        snapshot.recovery_pending = true;
        snapshot.pid = None;
        snapshot.requested_stop = false;
    }

    /// Marks the desktop-side state clean only after an independent recovery
    /// process has returned success and its journal has been verified.
    pub fn mark_recovery_complete(&mut self) {
        let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
        if !snapshot.recovery_pending {
            return;
        }
        snapshot.recovery_pending = false;
        snapshot.status = "disconnected".into();
        snapshot.phase = "idle".into();
        snapshot.pid = None;
        snapshot.requested_stop = false;
        snapshot.last_error.clear();
        let connection = snapshot.clone();
        drop(snapshot);
        (self.emit)(ProcessMessage {
            session_id: connection.session_id,
            event: ProcessEvent::State(connection.clone()),
            connection,
        });
    }

    /// Runs a fresh Core process in recovery-only mode. The worker is never
    /// stored in the normal child slot and cannot be mistaken for a VPN
    /// session. A non-zero exit or timeout leaves the journal retryable.
    pub fn run_recovery_worker(
        &mut self,
        spec: CommandSpec,
        timeout: Duration,
    ) -> Result<bool, ProcessError> {
        if self.is_running() {
            return Err(ProcessError::AlreadyRunning);
        }
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut worker = command.spawn().map_err(ProcessError::RecoverySpawn)?;
        let deadline = Instant::now() + timeout;
        loop {
            match worker.try_wait().map_err(ProcessError::RecoverySpawn)? {
                Some(status) => return Ok(status.success()),
                None if Instant::now() >= deadline => {
                    let _ = worker.kill();
                    let _ = worker.wait();
                    return Err(ProcessError::RecoveryTimeout);
                }
                None => thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    pub fn start(&mut self, spec: CommandSpec) -> Result<u32, ProcessError> {
        let mut slot = self.child.lock().expect("process lock poisoned");
        if slot.is_some() {
            return Err(ProcessError::AlreadyRunning);
        }
        // A pending marker is a recovery gate, not a permanent deadlock.  The
        // next Core invocation must be allowed to consume its journal before
        // applying new network state; Core remains fail-closed if recovery
        // cannot be verified.
        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn()?;
        let pid = child.id();
        *self
            .stop_context
            .lock()
            .expect("stop context lock poisoned") = StopContext::default();
        let session_id = {
            let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
            let session_id = snapshot.session_id + 1;
            *snapshot = ConnectionSnapshot {
                session_id,
                pid: Some(pid),
                status: "starting".into(),
                phase: "starting".into(),
                ..ConnectionSnapshot::default()
            };
            session_id
        };
        let snapshot = Arc::clone(&self.snapshot);
        let emitter = Arc::clone(&self.emit);
        let send: EventSink = Arc::new(move |event| {
            let mut current = snapshot.lock().expect("snapshot lock poisoned");
            if current.session_id != session_id {
                return;
            }
            current.apply(&event);
            let connection = current.clone();
            drop(current);
            emitter(ProcessMessage {
                session_id,
                event,
                connection,
            });
        });
        send(ProcessEvent::State(self.snapshot()));
        if let Some(stderr) = child.stderr.take() {
            let emit = Arc::clone(&send);
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    emit(ProcessEvent::Telemetry(classify_line(&line)));
                }
            });
        }
        *slot = Some(child);
        drop(slot);
        monitor_child(
            Arc::clone(&self.child),
            send,
            spec.stats_path,
            pid,
            Arc::clone(&self.stop_context),
            Arc::clone(&self.exiting),
        );
        Ok(pid)
    }

    pub fn stop(&mut self) -> Result<(), ProcessError> {
        self.stop_with_timeout(GRACEFUL_STOP_TIMEOUT)
    }

    /// Blocks until the monitor has emitted Exited for `pid`, so a restart
    /// cannot bump the session id before the old exit event is delivered.
    fn wait_exit_emitted(&self, pid: u32) {
        let (lock, cv) = &*self.exiting;
        let guard = lock.lock().expect("exiting lock poisoned");
        let _ = cv
            .wait_timeout_while(guard, Duration::from_secs(5), |p| *p == Some(pid))
            .expect("exiting lock poisoned");
    }

    fn stop_with_timeout(&mut self, graceful_timeout: Duration) -> Result<(), ProcessError> {
        let pid = match self.child.lock().expect("process lock poisoned").as_ref() {
            Some(child) => child.id(),
            None => return Ok(()),
        };
        self.stop_context
            .lock()
            .expect("stop context lock poisoned")
            .requested = true;
        let state = {
            let mut state = self.snapshot.lock().expect("snapshot lock poisoned");
            state.requested_stop = true;
            state.status = "stopping".into();
            state.clone()
        };
        (self.emit)(ProcessMessage {
            session_id: state.session_id,
            event: ProcessEvent::State(state.clone()),
            connection: state,
        });
        // The kernel rolls back routes, DNS and the adapter on shutdown; give it
        // time to finish before falling back to a hard kill.
        let graceful_requested = request_graceful_stop(pid);
        let grace = if graceful_requested {
            graceful_timeout
        } else {
            Duration::ZERO
        };
        let deadline = Instant::now() + grace;
        // Only this pid is ours to stop: a new session may start once it exits.
        let owns = |slot: &Option<Child>| slot.as_ref().is_some_and(|child| child.id() == pid);
        while Instant::now() < deadline {
            if !owns(&self.child.lock().expect("process lock poisoned")) {
                self.wait_exit_emitted(pid);
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        if graceful_requested {
            self.stop_context
                .lock()
                .expect("stop context lock poisoned")
                .timed_out = true;
            let timeout = {
                let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
                snapshot.status = "stop_timeout".into();
                snapshot.phase = "stop_timeout".into();
                snapshot.clone()
            };
            (self.emit)(ProcessMessage {
                session_id: timeout.session_id,
                event: ProcessEvent::State(timeout.clone()),
                connection: timeout,
            });
        }
        {
            let mut context = self
                .stop_context
                .lock()
                .expect("stop context lock poisoned");
            context.forced = true;
            context.recovery_pending = true;
        }
        let pending = {
            let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
            snapshot.status = "recovery_pending".into();
            snapshot.phase = "recovery_pending".into();
            snapshot.recovery_pending = true;
            snapshot.clone()
        };
        (self.emit)(ProcessMessage {
            session_id: pending.session_id,
            event: ProcessEvent::State(pending.clone()),
            connection: pending,
        });
        let exit = {
            let mut slot = self.child.lock().expect("process lock poisoned");
            match slot.as_mut().filter(|child| child.id() == pid) {
                Some(child) => {
                    child.kill().map_err(ProcessError::Stop)?;
                    let status = child.wait().map_err(ProcessError::Stop)?;
                    slot.take();
                    Some(ExitInfo {
                        code: status.code(),
                        success: false,
                        reason: ExitReason::ForcedKill,
                        timed_out: graceful_requested,
                        recovery_pending: true,
                    })
                }
                None => None,
            }
        };
        if exit.is_none() {
            self.wait_exit_emitted(pid);
        }
        if let Some(exit) = exit {
            let event = ProcessEvent::Exited(exit);
            let connection = {
                let mut snapshot = self.snapshot.lock().expect("snapshot lock poisoned");
                snapshot.apply(&event);
                snapshot.clone()
            };
            (self.emit)(ProcessMessage {
                session_id: connection.session_id,
                event,
                connection,
            });
        }
        Ok(())
    }
}

fn monitor_child(
    child: Arc<Mutex<Option<Child>>>,
    emit: EventSink,
    stats_path: Option<PathBuf>,
    pid: u32,
    stop_context: Arc<Mutex<StopContext>>,
    exiting: Arc<(Mutex<Option<u32>>, Condvar)>,
) {
    thread::spawn(move || {
        let mut offset = 0;
        let mut pending = String::new();
        let mut sampler = StatsSampler::default();
        loop {
            if !child
                .lock()
                .expect("process lock poisoned")
                .as_ref()
                .is_some_and(|child| child.id() == pid)
            {
                break;
            }
            if let Some(path) = &stats_path {
                read_stats(path, &mut offset, &mut pending, &mut sampler, &emit);
            }
            let exit = {
                let mut slot = child.lock().expect("process lock poisoned");
                if !slot.as_ref().is_some_and(|child| child.id() == pid) {
                    break;
                }
                match slot
                    .as_mut()
                    .and_then(|process| process.try_wait().ok())
                    .flatten()
                {
                    Some(status) => {
                        slot.take();
                        *exiting.0.lock().expect("exiting lock poisoned") = Some(pid);
                        Some(exit_info(status, &stop_context))
                    }
                    None => {
                        if slot.is_none() {
                            break;
                        }
                        None
                    }
                }
            };
            if let Some(exit) = exit {
                if let Some(path) = &stats_path {
                    read_stats(path, &mut offset, &mut pending, &mut sampler, &emit);
                }
                emit(ProcessEvent::Exited(exit));
                *exiting.0.lock().expect("exiting lock poisoned") = None;
                exiting.1.notify_all();
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
}

fn exit_info(status: std::process::ExitStatus, stop_context: &Arc<Mutex<StopContext>>) -> ExitInfo {
    let context = *stop_context
        .lock()
        .expect("stop context lock poisoned");
    ExitInfo {
        code: status.code(),
        success: status.success() && !context.forced,
        reason: if context.forced {
            ExitReason::ForcedKill
        } else if context.requested {
            ExitReason::Graceful
        } else {
            ExitReason::Natural
        },
        timed_out: context.timed_out,
        recovery_pending: context.recovery_pending,
    }
}

fn read_stats(
    path: &PathBuf,
    offset: &mut u64,
    pending: &mut String,
    sampler: &mut StatsSampler,
    emit: &EventSink,
) {
    let Ok(mut file) = std::fs::File::open(path) else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if metadata.len() < *offset {
        *offset = 0;
        pending.clear();
    }
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        return;
    }
    let mut chunk = String::new();
    if file.read_to_string(&mut chunk).is_err() {
        return;
    }
    *offset += chunk.len() as u64;
    pending.push_str(&chunk);
    while let Some(index) = pending.find('\n') {
        let line: String = pending.drain(..=index).collect();
        if let Ok(view) = sampler.consume_line(line.trim()) {
            emit(ProcessEvent::Stats(view));
        }
    }
}

const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Delivers CTRL_C_EVENT to the kernel's hidden console. `taskkill` without
/// `/F` only posts WM_CLOSE, which a windowless console process never sees.
#[cfg(windows)]
fn request_graceful_stop(pid: u32) -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn FreeConsole() -> i32;
        fn GenerateConsoleCtrlEvent(ctrl_event: u32, process_group_id: u32) -> i32;
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    const CTRL_C_EVENT: u32 = 0;
    static CONSOLE: Mutex<()> = Mutex::new(());
    let _guard = CONSOLE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return false;
        }
        // Ignore the event in this process. It stays ignored: the GUI never
        // handles Ctrl+C, and restoring it early could race the delivery.
        SetConsoleCtrlHandler(None, 1);
        let sent = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0;
        FreeConsole();
        sent
    }
}

#[cfg(unix)]
fn request_graceful_stop(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, libc::SIGTERM) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::sync::mpsc;

    #[cfg(unix)]
    #[test]
    fn forced_stop_reports_pending_recovery_and_never_success() {
        let (tx, rx) = mpsc::channel();
        let mut manager = ProcessManager::new(move |event| {
            let _ = tx.send(event);
        });
        manager
            .start(CommandSpec::new(
                "sh",
                ["-c", "trap '' TERM; while :; do true; done"],
            ))
            .unwrap();

        // Force the fallback path immediately; the command intentionally
        // ignores SIGTERM, so this exercises the durable recovery marker.
        manager.stop_with_timeout(Duration::ZERO).unwrap();

        let mut saw_pending = false;
        let mut forced_exit = None;
        while let Ok(event) = rx.recv_timeout(Duration::from_millis(500)) {
            match event.event {
                ProcessEvent::State(snapshot) if snapshot.status == "recovery_pending" => {
                    saw_pending = true;
                }
                ProcessEvent::Exited(exit) => {
                    forced_exit = Some(exit);
                    break;
                }
                _ => {}
            }
        }

        assert!(saw_pending);
        let exit = forced_exit.expect("forced stop must emit an exit event");
        assert_eq!(exit.reason, ExitReason::ForcedKill);
        assert!(exit.timed_out);
        assert!(!exit.success);
        assert!(exit.recovery_pending);
        assert_eq!(manager.snapshot().status, "recovery_pending");
        assert!(manager.snapshot().recovery_pending);
    }

    #[test]
    fn persisted_recovery_gate_allows_core_recovery_attempt() {
        let mut manager = ProcessManager::new(|_| {});
        manager.mark_recovery_pending();
        assert_eq!(manager.snapshot().status, "recovery_pending");
        assert!(manager.snapshot().recovery_pending);
        assert!(manager.start(CommandSpec::new("sh", ["-c", "exit 0"])).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_worker_is_separate_and_clears_state_only_after_success() {
        let mut manager = ProcessManager::new(|_| {});
        manager.mark_recovery_pending();
        let worker = CommandSpec::new("sh", ["-c", "exit 0", "--network-recovery"]);
        assert!(manager
            .run_recovery_worker(worker, Duration::from_secs(1))
            .unwrap());
        manager.mark_recovery_complete();
        assert!(!manager.snapshot().recovery_pending);
        assert_eq!(manager.snapshot().status, "disconnected");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_worker_failure_does_not_clear_pending_state() {
        let mut manager = ProcessManager::new(|_| {});
        manager.mark_recovery_pending();
        let worker = CommandSpec::new("sh", ["-c", "exit 7", "--network-recovery"]);
        assert!(!manager
            .run_recovery_worker(worker, Duration::from_secs(1))
            .unwrap());
        assert!(manager.snapshot().recovery_pending);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_worker_timeout_preserves_pending_state() {
        let mut manager = ProcessManager::new(|_| {});
        manager.mark_recovery_pending();
        let worker = CommandSpec::new("sh", ["-c", "sleep 2", "--network-recovery"]);
        let result = manager.run_recovery_worker(worker, Duration::from_millis(25));
        assert!(matches!(result, Err(ProcessError::RecoveryTimeout)));
        assert!(manager.snapshot().recovery_pending);
    }
}
