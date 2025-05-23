use aya::{
    maps::{perf::AsyncPerfEventArray, HashMap as AyaMap, MapData, StackTraceMap},
    programs::{perf_event, KProbe, PerfEvent, TracePoint, UProbe},
    util::online_cpus,
};
use bytes::BytesMut;
use clap::Parser;
use dashmap::DashMap;
use futures::{future::join_all, join};
use itertools::Itertools;
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use perf_bench::{
    gecko_profile::{
        MarkerDynamicField, MarkerFieldFormat, MarkerLocation, MarkerSchema, MarkerSchemaField,
        MarkerStaticField, ProfileBuilder, ProfilerMarker, ThreadBuilder,
    },
    symbolicate_stack_trace,
};
use perf_bench::{CliInputs, Sample2, StackInfo, Thread};
use proc_maps::MapRange;
use procfs::process::Process;
use rayon::prelude::*;
use rustc_demangle::demangle;
use serde_json::json;
use serde_json::to_writer;
use std::{cmp, io::Read};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    env,
    fs::File,
    io::BufWriter,
    ops::Range,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
#[rustfmt::skip]
use log::{debug, warn, info};
use perf_bench_common::{ProcessExecEvent, Sample, SAMPLE_PERIOD};
use std::sync::OnceLock;
use tokio::{
    select, signal,
    sync::{mpsc, watch, Mutex},
    task::{self, JoinHandle},
};
use uuid::Uuid;

static UPROBED_NAME: OnceLock<String> = OnceLock::new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let inputs = CliInputs::parse();

    let target_bin = inputs.binary;
    let target_funcs = [inputs.function];

    let mut file = File::open(&target_bin)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let obj_file = object::File::parse(&*buffer)?;
    let mut func_address_map: Vec<(String, u64)> = Vec::new();

    for symbol in obj_file.symbols() {
        if let Ok(name) = symbol.name() {
            let demangled_symbol = demangle(name).to_string();
            info!("failed to initialize eBPF logger: {}", demangled_symbol);
            if target_funcs.iter().any(|p| demangled_symbol.contains(p)) {
                func_address_map.push((name.to_string(), symbol.address()));
            }
        }
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let ebpf = Arc::new(Mutex::new(aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/perf-bench")
    ))?));

    let mut ebpf_guard = ebpf.lock().await;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf_guard) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let start_time = Instant::now();
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();
    // reconstruct the current time as a SystemTime instance
    let start_time_system = SystemTime::UNIX_EPOCH + Duration::from_millis(millis as u64);

    // Time since boot
    let start_timestamp_ns = get_timestamp_ns();

    let uprobe_program: &mut UProbe = ebpf_guard
        .program_mut("trace_uprobe_entry")
        .unwrap()
        .try_into()
        .unwrap();
    uprobe_program.load()?;

    let mut uprobed_name = String::new();
    for (func, address_offset) in &func_address_map {
        // let _ = UPROBED_NAME.set(func.to_owned());
        uprobed_name.push_str(func);
        uprobe_program.attach(None, *address_offset, &target_bin, None)?;
    }

    let uret_program: &mut UProbe = ebpf_guard
        .program_mut("trace_uprobe_exit")
        .unwrap()
        .try_into()
        .unwrap();
    uret_program.load()?;
    for (func, address_offset) in func_address_map {
        uret_program.attach(None, address_offset, &target_bin, None)?;
    }

    // Load and attach the tracepoint for context switches
    let tp: &mut TracePoint = ebpf_guard
        .program_mut("sched_switch")
        .unwrap()
        .try_into()
        .unwrap();
    tp.load()?;
    tp.attach("sched", "sched_switch")?;

    // `finish_task_switch` fn is called when kernel has completed context switching from
    // one task to another. It is part of the core scheduling infrastructure in the Kernel.
    // `isra`: fn was optimized by GCC with Interprocedural Scalar Replacement of Aggregates.
    // `.0`: version number
    // - it cleans up the previous task (like decrement reference count - struct task_struct)
    // - takes care of proper synchronization to ensure the task switch is
    //   complete before proceeding by memory barrier and locking.
    // - it handles scheduler statistics
    let kprobe: &mut KProbe = ebpf_guard
        .program_mut("finish_task_switch")
        .unwrap()
        .try_into()
        .unwrap();
    kprobe.load()?;
    match kprobe.attach("finish_task_switch", 0) {
        Ok(_) => (),
        Err(_) => {
            kprobe.attach("finish_task_switch.isra.0", 0)?;
        }
    }

    // This will raise scheduled events on each CPU at 1000000 HZ, triggered by the kernel based
    // on clock ticks.
    let program_perf_event: &mut PerfEvent =
        ebpf_guard.program_mut("cpu_clock").unwrap().try_into()?;
    program_perf_event.load()?;
    for cpu in online_cpus().map_err(|(_, error)| error)? {
        program_perf_event.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Period(SAMPLE_PERIOD),
            true,
        )?;
    }

    let mut perf_array = AsyncPerfEventArray::try_from(ebpf_guard.take_map("SAMPLES").unwrap())?;
    let stacks_traces = StackTraceMap::try_from(ebpf_guard.take_map("STACK_TRACES").unwrap())?;

    let (tx_pids, mut rx_pids) = mpsc::channel(32);
    let (termination_signal_sender, rx) = watch::channel(false);

    let mut rx_proc_maps_termination = rx.clone();
    let get_proc_maps = task::spawn(async move {
        // let mut process_cache = ProcessCache::default();
        let mut proc_maps_by_pid = HashMap::new();
        loop {
            select! {
                _termination_message = rx_proc_maps_termination.changed() => {
                    // Terminated.
                    break;
                }
                pid = rx_pids.recv() => {
                    if let Some(pid) = pid {
                        // process_cache.insert(pid as usize);
                        if proc_maps_by_pid.contains_key(&pid) {
                            continue;
                        }

                        let maps = match proc_maps::get_process_maps(pid as proc_maps::Pid) {
                            Ok(maps) => maps,
                            Err(_) => continue,
                        };
                        proc_maps_by_pid.insert(pid, maps);
                    }
                }
            }
        }
        // (proc_maps_by_pid, process_cache)
        proc_maps_by_pid
    });

    let mut join_handles = Vec::new();

    for cpu in online_cpus().map_err(|(_, error)| error)? {
        // TODO: would more than 2 pages in the perf array buffer be better?
        let mut buf = perf_array.open(cpu, Some(2))?;
        let mut rx = rx.clone();
        let tx_pids = tx_pids.clone();
        let task: JoinHandle<Result<_, anyhow::Error>> = task::spawn(async move {
            const SAMPLE_SIZE: usize = 60;
            const BUFFER_COUNT: usize = 10;
            let mut buffers = Vec::with_capacity(BUFFER_COUNT);
            let mut current_buffer = BytesMut::with_capacity(SAMPLE_SIZE * BUFFER_COUNT);
            for _ in 0..BUFFER_COUNT {
                let rest = current_buffer.split_off(SAMPLE_SIZE);
                buffers.push(current_buffer);
                current_buffer = rest;
            }

            let mut seen_pids = HashSet::new();

            let mut thread_samples = std::collections::HashMap::new();

            loop {
                select! {
                    _termination_message = rx.changed() => {
                        // Terminated.
                        break;
                    }
                    events = buf.read_events(&mut buffers) => {
                        let events = events?;
                        for buf in buffers.iter_mut().take(events.read) {
                            let data = unsafe { (buf.as_ptr() as *const Sample).read_unaligned() };
                            let thread_entry = thread_samples.entry(data.tid).or_insert_with(|| {
                                Thread {
                                    tid: data.tid,
                                    pid: None,
                                    name: None,
                                    samples: Vec::new(),
                                    is_kernel_thread: data.is_kernel_thread
                                }
                            });

                            if thread_entry.pid.is_none() && data.pid != 0 {
                                thread_entry.pid = Some(data.pid);

                                if !seen_pids.contains(&data.pid) {
                                    tx_pids.send(data.pid).await?;
                                    seen_pids.insert(data.pid);
                                }
                            }

                            if thread_entry.name.is_none() {
                                thread_entry.name = Some(comm_to_string(data.thread_name));
                            }

                            if data.is_on_cpu != 0 {
                                thread_entry.samples.push(Sample2{
                                    timestamp: data.timestamp,
                                    cpu_delta: data.cpu_delta,
                                    user_stack_id: data.user_stack_id,
                                    kernel_stack_id: data.kernel_stack_id,
                                    on_cpu: true,
                                });
                                // println!(
                                //     "{} | SAMPLE {:?} [{}]: ACTIVE with {}us CPU delta, stack {}, is_kernel_thread {}",
                                //     data.timestamp,
                                //     comm_to_string(data.thread_name),
                                //     data.tid,
                                //     data.cpu_delta / 1000,
                                //     data.user_stack_id,
                                //     data.is_kernel_thread
                                // );
                            } else {
                                let count = data.off_cpu_sample_count as u64;
                                let first_timestamp = data.timestamp - (count - 1) * SAMPLE_PERIOD;
                                thread_entry.samples.push(Sample2{
                                    timestamp: first_timestamp,
                                    cpu_delta: data.cpu_delta,
                                    user_stack_id: data.user_stack_id,
                                    kernel_stack_id: data.kernel_stack_id,
                                    on_cpu: false,
                                });
                                for i in 1..count {
                                    thread_entry.samples.push(Sample2{
                                        timestamp: first_timestamp + i * SAMPLE_PERIOD,
                                        cpu_delta: 0,
                                        user_stack_id: data.user_stack_id,
                                        kernel_stack_id: data.kernel_stack_id,
                                        on_cpu: false,
                                    });
                                }
                                // println!(
                                //     "{} | SAMPLE {:?} [{}]: INACTIVE with {}us CPU delta, stack {}, is_kernel_thread: {}",
                                //     data.timestamp,
                                //     comm_to_string(data.thread_name),
                                //     data.tid,
                                //     data.cpu_delta / 1000,
                                //     data.user_stack_id,
                                //     data.is_kernel_thread
                                // );
                            }
                        }
                    }
                }
            }
            Ok(thread_samples)
        });
        join_handles.push(task);
    }
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    let probed_pids: AyaMap<_, u8, ProcessExecEvent> =
        AyaMap::try_from(ebpf_guard.take_map("PROBED_PID_MAP").unwrap())?;
    let mut iter = probed_pids.iter();

    let probed_pid_info = if let Some(Ok(info)) = iter.next() {
        info
    } else {
        eprintln!("Probed pid info not found");
        drop(ebpf_guard);
        return Ok(());
    };
    println!("probed_pids: {:?}", probed_pid_info);

    println!("Exiting...");
    drop(ebpf_guard);
    eprintln!("bpf is dropped");
    termination_signal_sender.send(true)?;
    eprintln!("termination signal has been sent");
    let (proc_maps_by_pid, results) = join!(get_proc_maps, join_all(join_handles));

    // `thread_vecs` contains entries corresponding to each cpu. Merging it into one.
    let thread_vecs: Vec<Vec<_>> = results
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(Result::ok)
        .map(|map| map.into_values().collect())
        .collect();
    let threads = merge_threads(thread_vecs, comm_to_string(probed_pid_info.1.comm));

    // use std::fs::File;
    // use std::io::{BufWriter, Write};
    // let file = File::create("threads.json")?;
    // let mut writer = BufWriter::new(file);
    // serde_json::to_writer(&mut writer, &threads)?;
    // writer.flush()?;
    save_to_profile(
        start_time,
        start_timestamp_ns,
        start_time_system,
        &uprobed_name,
        threads,
        &stacks_traces,
        proc_maps_by_pid?,
        probed_pid_info.1,
    );
    Ok(())
}

fn merge_threads(thread_vecs: Vec<Vec<Thread>>, probed_comm: String) -> Vec<Thread> {
    let mut thread_map = HashMap::new();
    for thread_vec in thread_vecs {
        for thread in thread_vec {
            match thread_map.get_mut(&thread.tid) {
                Some(merged_thread) => merge_thread_into(thread, merged_thread, &probed_comm),
                None => {
                    thread_map.insert(thread.tid, thread);
                }
            }
        }
    }
    thread_map
        .into_values()
        .map(|mut thread| {
            thread.samples.sort_by_key(|s| s.timestamp);
            thread
        })
        .collect()
}

fn merge_thread_into(mut thread: Thread, merged_thread: &mut Thread, probed_comm: &String) {
    match (thread.pid, merged_thread.pid) {
        (Some(pid), None) => {
            merged_thread.pid = Some(pid);
        }
        (Some(pid1), Some(pid2)) if pid1 != pid2 => {
            eprintln!(
                "conflicting pids for tid {}: {} != {}",
                thread.tid, pid1, pid2
            );
        }
        _ => {}
    }
    match (thread.name, &merged_thread.name) {
        (Some(name), None) => {
            merged_thread.name = Some(name);
        }
        (Some(name1), Some(name2)) => {
            if name1.contains(probed_comm) || name2.contains(probed_comm) {
                merged_thread.name = Some(probed_comm.to_owned());
            } else if &name1 != name2 {
                eprintln!(
                    "conflicting names for tid {}: {} != {}",
                    thread.tid, name1, name2
                );
            }
        }
        _ => {}
    }
    merged_thread.samples.append(&mut thread.samples);
}

fn save_to_profile(
    start_time: Instant,
    start_timestamp_ns: u64,
    start_time_system: SystemTime,
    uprobed_name: &String,
    threads: Vec<Thread>,
    stack_traces: &StackTraceMap<MapData>,
    proc_maps_by_pid: HashMap<i32, Vec<MapRange>>,
    probed_pid_info: ProcessExecEvent,
) {
    let mut root_profile_builder = ProfileBuilder::new(
        start_time,
        start_time_system,
        "System",
        0,
        Duration::from_millis(1),
    );
    // let (threads_without_pid, threads_with_pid): (Vec<_>, Vec<_>) =
    //     threads.into_iter().partition(|t| t.pid.is_none());
    let (kernel_threads, userspace_threads): (Vec<_>, Vec<_>) =
        threads.into_iter().partition(|t| t.is_kernel_thread);
    let user_threads_by_pid = userspace_threads
        .into_iter()
        .into_group_map_by(|t| t.pid.unwrap());

    add_threads_to_profile(
        &mut root_profile_builder,
        start_time,
        start_timestamp_ns,
        uprobed_name,
        kernel_threads,
        stack_traces,
        probed_pid_info,
        None,
    );

    for (pid, threads) in user_threads_by_pid {
        let mut process_profile_builder = ProfileBuilder::new(
            start_time,
            start_time_system,
            "User process",
            pid as u32,
            Duration::from_millis(1),
        );
        let map_ranges = if let Some(map_ranges) = proc_maps_by_pid.get(&pid) {
            add_shared_libraries_to_profile(&mut process_profile_builder, map_ranges);
            Some(map_ranges)
        } else {
            None
        };
        info!(
            "Processing thread: {pid}, num of threads: {}",
            threads.len()
        );
        add_threads_to_profile(
            &mut process_profile_builder,
            start_time,
            start_timestamp_ns,
            &uprobed_name,
            threads,
            stack_traces,
            probed_pid_info,
            map_ranges.map(|v| &**v),
        );
        root_profile_builder.add_subprocess(process_profile_builder);
    }

    let file = File::create("profile.json").unwrap();
    let writer = BufWriter::new(file);
    to_writer(writer, &root_profile_builder.to_json()).expect("Couldn't write JSON");
}

fn add_threads_to_profile(
    profile_builder: &mut ProfileBuilder,
    start_time: Instant,
    start_timestamp_ns: u64,
    uprobed_name: &String,
    threads: Vec<Thread>,
    stack_traces: &StackTraceMap<MapData>,
    probed_pid_info: ProcessExecEvent,
    map_ranges: Option<&[MapRange]>,
) {
    let processed_thread_map: DashMap<Thread, ThreadBuilder> = DashMap::new();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(10)
        .build()
        .unwrap();

    pool.install(|| {
        threads.into_par_iter().for_each(|thread| {
            processed_thread_map
                .entry(thread.clone())
                .or_insert(make_profile_thread(
                    thread,
                    stack_traces,
                    start_time,
                    start_timestamp_ns,
                    uprobed_name,
                    probed_pid_info,
                    map_ranges,
                ));
        });
    });
    for (_key, value) in processed_thread_map.into_iter() {
        profile_builder.add_thread(value);
    }
}

fn make_profile_thread(
    thread: Thread,
    stack_traces: &StackTraceMap<MapData>,
    start_time: Instant,
    start_timestamp_ns: u64,
    uprobed_name: &String,
    probed_pid_info: ProcessExecEvent,
    map_ranges: Option<&[MapRange]>,
) -> ThreadBuilder {
    let mut thread_builder = ThreadBuilder::new(
        thread.pid.unwrap_or(0) as u32,
        thread.tid as u32,
        start_time,
        thread.pid == Some(thread.tid),
        false,
    );
    // if thread.pid == Some(thread.tid) {
    //     println!("{:?}", thread);
    // }

    if let Some(name) = thread.name.clone() {
        thread_builder.set_name(&name);
    }

    info!(
        "Processing thread: {}, num of samples: {}",
        thread.tid,
        thread.samples.len()
    );
    let mut stack_info_map = HashMap::new();

    for sample in thread.samples {
        let timestamp_rel_ms = (sample.timestamp - start_timestamp_ns) as f64 / 1_000_000.0;
        let cpu_delta_us = sample.cpu_delta / 1_000;
        // println!(
        //     "thread_id: {:?}, thread name : {:?}",
        //     thread.tid,
        //     thread.name.clone().unwrap()
        // );
        let stack_info = StackInfo {
            tid: thread.tid,
            pid: thread.pid,
            user_stack_id: sample.user_stack_id,
            kernel_stack_id: sample.kernel_stack_id,
            name: thread.name.clone().unwrap_or("unnamed".to_string()),
            is_kernel_thread: thread.is_kernel_thread,
        };

        match stack_info_map.get(&stack_info) {
            Some(stack_index) => {
                thread_builder.add_sample_same_stack(timestamp_rel_ms, *stack_index, cpu_delta_us);
            }
            None => {
                let combined = symbolicate_stack_trace(&stack_info, stack_traces, map_ranges);
                // println!("{:?}", combined);
                let stack_index =
                    thread_builder.add_sample(timestamp_rel_ms, combined.as_slice(), cpu_delta_us);
                stack_info_map.insert(stack_info, stack_index);
            }
        }
    }

    if thread.name == Some(comm_to_string(probed_pid_info.comm)) && thread.pid == Some(thread.tid) {
        let timestamp_rel_ns_start =
            (probed_pid_info.start_time - start_timestamp_ns) as f64 / 1_000_000.0;
        let timestamp_rel_ns_end =
            (probed_pid_info.end_time - start_timestamp_ns) as f64 / 1_000_000.0;

        let uprobe_start_time = bpf_time_to_instant(probed_pid_info.start_time, start_timestamp_ns);
        let uprobe_end_time = bpf_time_to_instant(probed_pid_info.end_time, start_timestamp_ns);
        // println!("uprobe_start_time: {:?}", uprobe_start_time);
        // println!("uprobe_end_time: {:?}", uprobe_end_time);
        let uprobed_default_name = "Uprobed".to_string();
        // let uprobed_name = UPROBED_NAME.get().unwrap_or(&uprobed_default_name);
        thread_builder.add_marker(
            uprobed_name,
            CustomMarker {
                event_name: uprobed_name.to_string(),
                latency: Duration::from_millis(
                    probed_pid_info.end_time - probed_pid_info.start_time,
                ),
            },
            timestamp_rel_ns_start,
            timestamp_rel_ns_end,
        );
    }

    thread_builder
}

fn add_shared_libraries_to_profile(profile_builder: &mut ProfileBuilder, map_ranges: &[MapRange]) {
    let mut exec_ranges_by_path: HashMap<String, Range<u64>> = HashMap::new();
    for range in map_ranges {
        if !range.is_exec() {
            continue;
        }
        let path = match range.filename() {
            Some(path) => path.to_string_lossy().to_string(),
            _ => continue,
        };
        let address_range = (range.start()) as u64..(range.start() + range.size()) as u64;
        // if path.contains("libxul") {
        //     eprintln!("adding range {:x}-{:x} with {:?}", address_range.start, address_range.end, range.is_exec());
        // }
        match exec_ranges_by_path.get_mut(&path) {
            Some(rg) => {
                rg.start = rg.start.min(address_range.start);
                rg.end = rg.end.min(address_range.end);
            }
            None => {
                exec_ranges_by_path.insert(path, address_range);
            }
        }
    }
    for range in map_ranges {
        let path = match range.filename() {
            Some(path) => path.to_string_lossy().to_string(),
            _ => continue,
        };
        // if path.contains("libxul") {
        //     eprintln!("adding range {:x}-{:x} with {:?}", address_range.start, address_range.end, range.is_exec());
        // }
        if let Some(rg) = exec_ranges_by_path.get_mut(&path) {
            rg.start = rg.start.min(range.start() as u64);
        }
    }

    // eprintln!("ranges_by_path: {:#?}", ranges_by_path);

    for (path, address_range) in exec_ranges_by_path {
        if path.contains("libxul") {
            eprintln!(
                "{:x}-{:x} exec? {:?}",
                address_range.start, address_range.end, path
            );
        }
        let p = Path::new(&path);
        if let Ok(file) = File::open(p) {
            if let Ok(mmap) = unsafe { memmap2::MmapOptions::new().map(&file) } {
                if let Ok(f) = object::File::parse(&mmap[..]) {
                    if let Some(uuid) = get_elf_id(&f) {
                        let name = p.file_name().unwrap().to_str().unwrap();
                        if path.contains("libxul") {
                            eprintln!("got to adding");
                        }
                        profile_builder.add_lib(name, &path, &uuid, "", &address_range);
                    }
                }
            }
        }
    }
}

const UUID_SIZE: usize = 16;
const PAGE_SIZE: usize = 4096;

fn create_elf_id(identifier: &[u8], little_endian: bool) -> Uuid {
    // Make sure that we have exactly UUID_SIZE bytes available
    let mut data = [0u8; UUID_SIZE];
    let len = cmp::min(identifier.len(), UUID_SIZE);
    data[0..len].copy_from_slice(&identifier[0..len]);

    if little_endian {
        // The file ELF file targets a little endian architecture. Convert to
        // network byte order (big endian) to match the Breakpad processor's
        // expectations. For big endian object files, this is not needed.
        data[0..4].reverse(); // uuid field 1
        data[4..6].reverse(); // uuid field 2
        data[6..8].reverse(); // uuid field 3
    }

    Uuid::from_bytes(data)
}
/// Tries to obtain the object identifier of an ELF object.
///
/// As opposed to Mach-O, ELF does not specify a unique ID for object files in
/// its header. Compilers and linkers usually add either `SHT_NOTE` sections or
/// `PT_NOTE` program header elements for this purpose. If one of these notes
/// is present, ElfFile's build_id() method will find it.
///
/// If neither of the above are present, this function will hash the first page
/// of the `.text` section (program code). This matches what the Breakpad
/// processor does.
///
/// If all of the above fails, this function will return `None`.
pub fn get_elf_id<'data: 'file, 'file>(elf_file: &'file impl Object<'data>) -> Option<Uuid> {
    if let Some(identifier) = elf_file.build_id().ok()? {
        return Some(create_elf_id(identifier, elf_file.is_little_endian()));
    }

    // We were not able to locate the build ID, so fall back to hashing the
    // first page of the ".text" (program code) section. This algorithm XORs
    // 16-byte chunks directly into a UUID buffer.
    if let Some(section_data) = find_text_section(elf_file) {
        let mut hash = [0; UUID_SIZE];
        for i in 0..cmp::min(section_data.len(), PAGE_SIZE) {
            hash[i % UUID_SIZE] ^= section_data[i];
        }

        return Some(create_elf_id(&hash, elf_file.is_little_endian()));
    }

    None
}

/// Returns a reference to the data of the the .text section in an ELF binary.
fn find_text_section<'data: 'file, 'file>(file: &'file impl Object<'data>) -> Option<&'data [u8]> {
    file.sections()
        .find(|header| header.kind() == SectionKind::Text)
        .and_then(|header| header.data().ok())
}

fn get_timestamp_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Time since boot (no NTP adjustments)
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    (time.tv_sec * 1_000_000_000 + time.tv_nsec) as u64
}

fn bpf_ktime_to_instant(bpf_ktime_ns: u64, boot_offset: Duration) -> Instant {
    let elapsed_since_boot = Duration::from_nanos(bpf_ktime_ns);
    let now = Instant::now();
    // Instant::now() is 'now = boot + boot_offset'
    // So: bpf_time = boot + elapsed_since_boot
    // => delta = elapsed_since_boot - boot_offset
    // if elapsed_since_boot > boot_offset {
    now - (elapsed_since_boot - boot_offset)
    // } else {
    // now + (boot_offset - elapsed_since_boot)
    // }
}

// Convert bpf_ktime_get_ns() timestamp to Instant
fn bpf_time_to_instant(bpf_timestamp: u64, time_since_boot: u64) -> Instant {
    let now = Instant::now();
    let millis_since_baseline = bpf_timestamp.saturating_sub(time_since_boot) / 1_000_000;
    now + Duration::from_millis(millis_since_baseline)
}

fn get_thread_name(pid: i32, tid: i32) -> String {
    if let Ok(p) = Process::new(pid) {
        if let Ok(tasks) = p.tasks() {
            let t = tasks
                .filter(|t| t.as_ref().unwrap().tid == tid)
                .collect::<Vec<_>>();
            t[0].as_ref().unwrap().stat().unwrap().comm
        } else {
            "unnamed".to_string()
        }
        // println!(
        //     "{:?}: {:?}",
        //     t.as_ref().unwrap().tid,
        //     t.as_ref().unwrap().stat().unwrap().comm
        // );
    } else {
        "unnamed".to_string()
    }
}

fn comm_to_string(comm: [u8; 16]) -> String {
    let len = comm.iter().position(|&c| c == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).to_string()
}

struct CustomMarker {
    event_name: String,
    latency: Duration,
}
impl ProfilerMarker for CustomMarker {
    const MARKER_TYPE_NAME: &'static str = "custom";

    fn schema() -> MarkerSchema {
        MarkerSchema {
            type_name: Self::MARKER_TYPE_NAME,
            locations: vec![MarkerLocation::MarkerChart, MarkerLocation::MarkerTable],
            chart_label: None,
            tooltip_label: Some("Total Time"),
            table_label: None,
            fields: vec![
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "eventName",
                    label: "Event name",
                    format: MarkerFieldFormat::String,
                    searchable: None,
                }),
                MarkerSchemaField::Dynamic(MarkerDynamicField {
                    key: "latency",
                    label: "Latency",
                    format: MarkerFieldFormat::Duration,
                    searchable: None,
                }),
                MarkerSchemaField::Static(MarkerStaticField {
                    label: "Description",
                    value: "This is a test marker with a custom schema.",
                }),
            ],
        }
    }

    fn json_marker_data(&self) -> serde_json::Value {
        json!({
            "type": Self::MARKER_TYPE_NAME,
            "eventName": self.event_name,
            "latency": self.latency.as_secs_f64() * 1000.0,
        })
    }
}
