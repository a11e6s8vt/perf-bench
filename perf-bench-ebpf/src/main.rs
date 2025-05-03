#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(unused)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
mod bindings;
mod sched_process_fork;
use core::{ffi::CStr, ptr::null};

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    bpf_printk,
    cty::{c_char, c_long, c_schar},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task_btf,
        bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, perf_event, tracepoint, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray, StackTrace},
    programs::{PerfEventContext, ProbeContext, RetProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::{debug, error, info};
use bindings::{
    bpf_perf_event_data, mm_struct, pid_t, pt_regs, task_struct, thread_struct,
    trace_event_raw_sched_switch,
};
use memoffset::offset_of;
use perf_bench_common::{CommData, ProcessExecEvent, Sample, SchedSwitchEvent, TaskInfo, ThreadId};
use sched_process_fork::trace_event_raw_sched_process_fork;

#[derive(Clone)]
struct ThreadTimingData {
    active: u64,
    /// we sample every time this overflows sample_period
    off_cpu_wrapping_counter_ns: u64,
    /// set to zero after every sample
    cpu_delta_since_last_sample_ns: u64,
    /// set to the current timestamp on on/sample/off
    last_seen_ts: u64,
    /// set to the current user stack when going off
    user_stack_when_going_off: i64,

    /// set to the kernel user stack when going off
    kernel_stack_when_going_off: i64,
}

#[map(name = "TASK_INFO_MAP")]
static mut TASK_INFO_MAP: HashMap<i32, TaskInfo> =
    HashMap::<i32, TaskInfo>::with_max_entries(102400, 0);

#[map(name = "PROBED_PID_MAP")]
static mut PROBED_PID_MAP: HashMap<i32, ProcessExecEvent> =
    HashMap::<i32, ProcessExecEvent>::with_max_entries(1024, 0);

#[map(name = "SAMPLES")]
static mut SAMPLES: PerfEventArray<Sample> = PerfEventArray::<Sample>::new(0);

#[map(name = "STACK_TRACES")]
static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(102400, 0);

#[map(name = "THREAD_TIMING")]
static mut THREAD_TIMING: HashMap<i32, ThreadTimingData> = HashMap::with_max_entries(1024, 0);

static SAMPLE_PERIOD_NS: u64 = 999999;
const PARENT_COMM_OFFSET: usize = 8;
const PARENT_PID_OFFSET: usize = 24;
const CHILD_COMM_OFFSET: usize = 28;
const CHILD_PID_OFFSET: usize = 44;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
fn get_thread_timing(pid: i32, now: u64, active: bool) -> ThreadTimingData {
    match unsafe { THREAD_TIMING.get(&pid) } {
        Some(timing) => timing.clone(),
        None => ThreadTimingData {
            active: active as u64,
            off_cpu_wrapping_counter_ns: 0,
            cpu_delta_since_last_sample_ns: 0,
            last_seen_ts: now,
            user_stack_when_going_off: -1,
            kernel_stack_when_going_off: -1,
        },
    }
}

#[inline(always)]
fn set_thread_timing(pid: i32, timing: &ThreadTimingData) {
    let _ = unsafe { THREAD_TIMING.insert(&pid, timing, 0) };
}

#[inline(always)]
fn thread_goes_on(ctx: &impl EbpfContext, pid: i32, tgid: i32, now: u64, comm: &[u8; 16usize]) {
    let comm_str = unsafe { core::str::from_utf8_unchecked(comm) };
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let is_kernel_thread = if let Some(info) = unsafe { TASK_INFO_MAP.get(&pid) } {
        let is_kernel_thread = if comm_str == unsafe { core::str::from_utf8_unchecked(&info.comm) }
        {
            info.is_kernel_thread
        } else {
            false
        };
        is_kernel_thread
    } else {
        false
    };

    let mut timing = get_thread_timing(pid, now, false);
    let sleep_time: u64 = now - timing.last_seen_ts;
    timing.off_cpu_wrapping_counter_ns += sleep_time;
    let off_cpu_sample_count = timing.off_cpu_wrapping_counter_ns / SAMPLE_PERIOD_NS;
    if off_cpu_sample_count > 0 {
        timing.off_cpu_wrapping_counter_ns -= off_cpu_sample_count * SAMPLE_PERIOD_NS;
        let sample = Sample {
            cpu,
            timestamp: now,
            cpu_delta: timing.cpu_delta_since_last_sample_ns,
            pid: tgid,
            tid: pid,
            is_on_cpu: 0,
            off_cpu_sample_count: off_cpu_sample_count as u32,
            user_stack_id: timing.user_stack_when_going_off,
            kernel_stack_id: timing.kernel_stack_when_going_off,
            thread_name: *comm,
            is_kernel_thread,
        };
        unsafe { SAMPLES.output(ctx, &sample, 0) };
        timing.cpu_delta_since_last_sample_ns = 0;
    }
    timing.last_seen_ts = now;
    timing.active = 1;
    set_thread_timing(pid, &timing);
}

#[inline(always)]
fn thread_goes_off(ctx: &impl EbpfContext, pid: i32, _tgid: i32, now: u64) {
    let mut timing = get_thread_timing(pid, now, true);
    let on_cpu_time_delta = now - timing.last_seen_ts;
    timing.cpu_delta_since_last_sample_ns += on_cpu_time_delta;
    timing.last_seen_ts = now;
    timing.active = 0;
    timing.user_stack_when_going_off =
        match unsafe { STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK.into()) } {
            Ok(stack) => stack,
            Err(e) => e,
        };
    timing.kernel_stack_when_going_off = match unsafe { STACK_TRACES.get_stackid(ctx, 0) } {
        Ok(stack) => stack,
        Err(e) => e,
    };
    set_thread_timing(pid, &timing);
}

#[inline(always)]
fn thread_gets_sampled_while_on(
    ctx: &impl EbpfContext,
    cpu: u32,
    pid: i32,
    tgid: i32,
    now: u64,
    comm: [u8; 16],
) {
    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    // debug!(
    //     ctx,
    //     "tgswo - next_tgid: {} {} {}",
    //     ctx.tgid(),
    //     ctx.pid(),
    //     comm_str
    // );
    let mut timing = get_thread_timing(pid, now, true);
    if timing.active == 0 {
        return;
    }
    let on_cpu_time_delta = now - timing.last_seen_ts;
    timing.cpu_delta_since_last_sample_ns += on_cpu_time_delta;
    let user_stack_id = match unsafe { STACK_TRACES.get_stackid(ctx, BPF_F_USER_STACK.into()) } {
        Ok(stack) => stack,
        Err(e) => e,
    };
    let kernel_stack_id = match unsafe { STACK_TRACES.get_stackid(ctx, 0) } {
        Ok(stack) => stack,
        Err(e) => e,
    };

    let is_kernel_thread = if let Some(info) = unsafe { TASK_INFO_MAP.get(&pid) } {
        let is_kernel_thread = if unsafe { core::str::from_utf8_unchecked(&comm) }
            == unsafe { core::str::from_utf8_unchecked(&info.comm) }
        {
            info.is_kernel_thread
        } else {
            false
        };
        is_kernel_thread
    } else {
        false
    };

    // debug!(
    //     &ctx,
    //     "next_tgid: {} {} {}",
    //     next_tgid,
    //     next_pid,
    //     core::str::from_utf8_unchecked(&next_comm)
    // );
    let sample = Sample {
        cpu,
        timestamp: now,
        cpu_delta: timing.cpu_delta_since_last_sample_ns,
        pid: tgid,
        tid: pid,
        is_on_cpu: 1,
        off_cpu_sample_count: 0,
        user_stack_id,
        kernel_stack_id,
        thread_name: comm,
        is_kernel_thread,
    };

    unsafe { SAMPLES.output(ctx, &sample, 0) };

    timing.cpu_delta_since_last_sample_ns = 0;
    timing.last_seen_ts = now;
    set_thread_timing(pid, &timing);
}

#[uprobe]
pub fn trace_uprobe_entry(ctx: ProbeContext) -> i32 {
    info!(&ctx, "entry called");
    match unsafe { try_trace_uprobe_entry(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_trace_uprobe_entry(ctx: &ProbeContext) -> Result<i32, c_long> {
    let tid = ctx.pid() as pid_t;
    let pid = ctx.tgid() as pid_t;
    let comm = ctx.command()?;

    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let now = bpf_ktime_get_ns();
    info!(ctx, "entry updated {} {} {}", pid, tid, comm_str);
    let info = ProcessExecEvent {
        tid,
        pid,
        comm,
        start_time: now,
        end_time: 0,
    };
    PROBED_PID_MAP.insert(&tid, &info, 0)?;

    Ok(0)
}

#[uretprobe]
pub fn trace_uprobe_exit(ctx: RetProbeContext) -> i32 {
    info!(&ctx, "exit called");
    match unsafe { try_trace_uprobe_exit(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_trace_uprobe_exit(ctx: &RetProbeContext) -> Result<i32, c_long> {
    let tid = ctx.pid() as pid_t;
    let pid = ctx.tgid() as pid_t;
    let comm = ctx.command()?;

    let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    let now = bpf_ktime_get_ns();
    if let Some(exec_event) = unsafe { PROBED_PID_MAP.get(&tid) } {
        let exec_event = ProcessExecEvent {
            tid: exec_event.tid,
            pid: exec_event.pid,
            comm: exec_event.comm,
            start_time: exec_event.start_time,
            end_time: exec_event.end_time,
        };
        PROBED_PID_MAP.insert(&tid, &exec_event, 0);
    }
    info!(ctx, "exit updated {} {} {}", pid, tid, comm_str);
    Ok(0)
}

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match unsafe { try_sched_switch(ctx) } {
        Ok(ret) => ret,
        Err(_e) => 1,
    }
}

#[inline(always)]
pub unsafe fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    let prev_pid = bpf_probe_read(
        ctx.as_ptr()
            .offset(offset_of!(trace_event_raw_sched_switch, prev_pid) as isize)
            as *const pid_t,
    )?;
    let next_pid = bpf_probe_read(
        ctx.as_ptr()
            .offset(offset_of!(trace_event_raw_sched_switch, next_pid) as isize)
            as *const pid_t,
    )?;
    let now = bpf_ktime_get_ns();

    if prev_pid != 0 {
        let prev_tgid = 0;
        let prev_comm_offset = core::mem::offset_of!(trace_event_raw_sched_switch, prev_comm);
        let prev_comm = unsafe {
            bpf_probe_read(ctx.as_ptr().offset(prev_comm_offset as isize)
                as *const [::aya_ebpf::cty::c_uchar; 16usize])?
        };

        let prev_tgid = if let Some(info) = unsafe { TASK_INFO_MAP.get(&prev_pid) } {
            let tgid = if core::str::from_utf8_unchecked(&prev_comm)
                == core::str::from_utf8_unchecked(&info.comm)
            {
                info.pid
            } else {
                0
            };
            tgid
        } else {
            0
        };

        // debug!(
        //     &ctx,
        //     "prev_tgid: {} {} {}",
        //     prev_tgid,
        //     prev_pid,
        //     core::str::from_utf8_unchecked(&prev_comm)
        // );
        thread_goes_off(&ctx, prev_pid, prev_tgid, now);
    }

    if next_pid != 0 {
        let next_comm_offset = core::mem::offset_of!(trace_event_raw_sched_switch, next_comm);
        let next_comm = unsafe {
            bpf_probe_read(ctx.as_ptr().offset(next_comm_offset as isize)
                as *const [::aya_ebpf::cty::c_uchar; 16usize])?
        };

        let next_tgid = if let Some(info) = unsafe { TASK_INFO_MAP.get(&next_pid) } {
            let tgid = if core::str::from_utf8_unchecked(&next_comm)
                == core::str::from_utf8_unchecked(&info.comm)
            {
                info.pid
            } else {
                0
            };
            tgid
        } else {
            0
        };

        // debug!(
        //     &ctx,
        //     "next_tgid: {} {} {}",
        //     next_tgid,
        //     next_pid,
        //     core::str::from_utf8_unchecked(&next_comm)
        // );
        thread_goes_on(&ctx, next_pid, next_tgid as i32, now, &next_comm);
    }
    Ok(0)
}

#[perf_event]
pub fn cpu_clock(ctx: PerfEventContext) -> Result<u32, i64> {
    if ctx.pid() == 0 {
        return Ok(0);
    }

    let cpu = unsafe { bpf_get_smp_processor_id() };
    let now = unsafe { bpf_ktime_get_ns() };
    // let comm: [u8; 16] = match bpf_get_current_comm() {
    //     // Ok(comm) => unsafe { core::mem::transmute(comm) },
    //     Ok(comm) => comm,
    //     Err(_) => return 0,
    // };
    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };
    if task.is_null() {
        return Err(1);
    }

    // The thread ID (TID). Unique for each thread.
    // let pid = unsafe { bpf_probe_read_kernel(&(*task).pid)? };

    // The process ID (PID). Same for all threads of the same process.
    // let tgid = unsafe { bpf_probe_read_kernel(&(*task).tgid)? };

    // Get the comm (process name).
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(ret) => return Err(ret),
    };
    // let comm_str = unsafe { core::str::from_utf8_unchecked(&comm) };
    // debug!(&ctx, "next_tgid: {} {} {}", ctx.tgid(), ctx.pid(), comm_str);

    thread_gets_sampled_while_on(&ctx, cpu, ctx.pid() as i32, ctx.tgid() as i32, now, comm);

    Ok(0)
}

#[kprobe]
pub fn finish_task_switch(ctx: ProbeContext) -> u32 {
    match unsafe { try_finish_task_switch(ctx) } {
        Ok(ret) => ret,
        Err(_e) => 0,
    }
}

#[inline(always)]
pub unsafe fn try_finish_task_switch(ctx: ProbeContext) -> Result<u32, i64> {
    // Get arguments as raw pointers
    let task: *const task_struct = ctx.arg(0).ok_or(1)?;

    // Read values from task_struct
    let comm = bpf_probe_read_kernel(&(*task).comm as *const [::aya_ebpf::cty::c_char; 16usize])?;
    let comm = core::mem::transmute::<[i8; 16], [u8; 16]>(comm);
    let tgid = bpf_probe_read_kernel(&(*task).tgid as *const pid_t)?;
    let tid = bpf_probe_read_kernel(&(*task).pid as *const pid_t)?;

    let mm = bpf_probe_read_kernel(&(*task).mm as &*mut mm_struct)?;
    let is_kernel_thread = if mm.is_null() { true } else { false };

    let info = TaskInfo {
        pid: tgid,
        tid,
        comm,
        is_kernel_thread,
    };
    // // bpf_printk!(b"---------------- command: %s", child_comm.as_ptr());
    //
    TASK_INFO_MAP.insert(&tid, &info, 0)?;
    // let kt = if is_kernel_thread { 1 } else { 0 };
    // let comm = core::str::from_utf8_unchecked(&comm);
    // info!(
    //     &ctx,
    //     "wake_up_new_task. comm: {}, tgid: {}, tid: {} {}.", comm, tgid, tid, kt
    // );

    Ok(0)
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
