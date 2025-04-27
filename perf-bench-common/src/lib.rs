#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEvent {
    pub tag: u64,
    pub field: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LogEvent {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub cpu: u32,
    pub timestamp: u64,
    pub cpu_delta: u64,
    // The process ID (PID). Same for all threads of the same process.
    pub pid: i32,
    // The thread ID (TID). Unique for each thread.
    pub tid: i32,
    pub is_on_cpu: u32,
    pub off_cpu_sample_count: u32,
    pub kernel_stack_id: i64,
    pub user_stack_id: i64,
    pub thread_name: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl Send for Sample {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Sample {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ThreadId {
    pub tid: i32,
}

#[cfg(feature = "user")]
unsafe impl Send for ThreadId {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ThreadId {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CommData {
    /// TGID
    pub pid: i32,
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl Send for CommData {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CommData {}
