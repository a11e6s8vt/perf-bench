use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod cache;
pub mod gecko_profile;
pub mod process;
pub mod profiler;
pub mod symbols;

pub use cache::*;
pub use gecko_profile::*;
pub use process::*;
pub use profiler::*;
pub use symbols::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[derive(Debug, Deserialize)]
pub struct CliInputs {
    #[arg(short, long, value_name = "binary")]
    pub binary: PathBuf,

    #[arg(short, long, value_name = "function")]
    pub function: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct StackInfo {
    /// LWP — thread ID (PID of the individual thread, different from TGID if multi-threaded)
    pub tid: i32,
    pub user_stack_id: i64,
    pub kernel_stack_id: i64,
    pub name: String,
    pub is_kernel_thread: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    /// LWP — thread ID (PID of the individual thread, different from TGID if multi-threaded)
    pub tid: i32,
    /// PID — process ID (TGID, thread group leader)
    pub pid: Option<i32>,
    pub name: Option<String>,
    pub samples: Vec<Sample2>,
    pub is_kernel_thread: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Sample2 {
    pub timestamp: u64,
    pub cpu_delta: u64,
    pub user_stack_id: i64,
    pub kernel_stack_id: i64,
    pub on_cpu: bool,
}
