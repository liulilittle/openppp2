pub mod config;
pub mod connection;
mod desktop;
pub mod launch_options;
pub mod lifecycle;
pub mod manual_nodes;
pub mod pinger;
pub mod preferences;
pub mod process;
pub mod stats;
pub mod subscription;
pub mod telemetry;
pub mod windows;
pub mod storage;
pub mod kernel;
pub mod network;
pub mod policy;

pub use desktop::run;
