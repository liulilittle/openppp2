use crate::stats::{StatsSampler, StatsView};
use crate::telemetry::{classify_line, TelemetryEvent};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "lowercase")]
pub enum ProcessEvent {
    Telemetry(TelemetryEvent),
    Stats(StatsView),
    Exited(ExitInfo),
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("ppp 进程已在运行中")]
    AlreadyRunning,
    #[error("无法启动 ppp: {0}")]
    Spawn(#[from] std::io::Error),
}

type Emitter = Arc<dyn Fn(ProcessEvent) + Send + Sync + 'static>;

pub struct ProcessManager {
    child: Arc<Mutex<Option<Child>>>,
    emit: Emitter,
}

impl ProcessManager {
    pub fn new<F>(emit: F) -> Self
    where
        F: Fn(ProcessEvent) + Send + Sync + 'static,
    {
        Self {
            child: Arc::new(Mutex::new(None)),
            emit: Arc::new(emit),
        }
    }

    pub fn is_running(&self) -> bool {
        self.child.lock().expect("process lock poisoned").is_some()
    }

    pub fn start(&mut self, spec: CommandSpec) -> Result<u32, ProcessError> {
        let mut slot = self.child.lock().expect("process lock poisoned");
        if slot.is_some() {
            return Err(ProcessError::AlreadyRunning);
        }
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
        if let Some(stderr) = child.stderr.take() {
            let emit = Arc::clone(&self.emit);
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
            Arc::clone(&self.emit),
            spec.stats_path,
        );
        Ok(pid)
    }

    pub fn stop(&mut self) -> Result<(), ProcessError> {
        let pid = match self.child.lock().expect("process lock poisoned").as_ref() {
            Some(child) => child.id(),
            None => return Ok(()),
        };
        request_graceful_stop(pid);
        let deadline = Instant::now() + Duration::from_millis(750);
        while Instant::now() < deadline {
            if !self.is_running() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(25));
        }
        if let Some(child) = self.child.lock().expect("process lock poisoned").as_mut() {
            child.kill()?;
        }
        Ok(())
    }
}

fn monitor_child(child: Arc<Mutex<Option<Child>>>, emit: Emitter, stats_path: Option<PathBuf>) {
    thread::spawn(move || {
        let mut offset = 0;
        let mut pending = String::new();
        let mut sampler = StatsSampler::default();
        loop {
            if let Some(path) = &stats_path {
                read_stats(path, &mut offset, &mut pending, &mut sampler, &emit);
            }
            let exit = {
                let mut slot = child.lock().expect("process lock poisoned");
                match slot
                    .as_mut()
                    .and_then(|process| process.try_wait().ok())
                    .flatten()
                {
                    Some(status) => {
                        slot.take();
                        Some(ExitInfo {
                            code: status.code(),
                            success: status.success(),
                        })
                    }
                    None => None,
                }
            };
            if let Some(exit) = exit {
                if let Some(path) = &stats_path {
                    read_stats(path, &mut offset, &mut pending, &mut sampler, &emit);
                }
                emit(ProcessEvent::Exited(exit));
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
}

fn read_stats(
    path: &PathBuf,
    offset: &mut u64,
    pending: &mut String,
    sampler: &mut StatsSampler,
    emit: &Emitter,
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

#[cfg(windows)]
fn request_graceful_stop(pid: u32) {
    use std::os::windows::process::CommandExt;
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .creation_flags(0x0800_0000)
        .status();
}

#[cfg(unix)]
fn request_graceful_stop(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}
