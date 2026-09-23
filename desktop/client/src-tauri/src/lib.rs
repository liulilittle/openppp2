pub mod config;
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

pub use desktop::run;
