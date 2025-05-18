use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    f64,
};
use uuid::Uuid;

use std::cmp::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::markers::*;
use crate::symbolicate::StackFrameInfo;

pub type Result<T> = std::result::Result<T, anyhow::Error>;

fn all_categories_1() -> Vec<Value> {
    vec![
        json!({
            "color": "yellow",
            "name": "User",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "orange",
            "name": "Kernel",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "yellow",
            "name": "Native",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "green",
            "name": "DEX",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "green",
            "name": "OAT",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "blue",
            "name": "Off-CPU",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "grey",
            "name": "Other",
            "subcategories": ["Other"]
        }),
        json!({
            "color": "green",
            "name": "JIT",
            "subcategories": ["Other"]
        }),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "PascalCase")]
pub enum Category {
    User = 0,
    Kernel = 1,
    Native = 2,
    Dex = 3,
    Oat = 4,
    OffCpu = 5,
    Jit = 6,
    Other = 7,
}

fn categorize_frame(dso_path: &str, symbol: &str) -> Category {
    let path = dso_path.to_lowercase();

    if path.contains("libart") || path.contains("dex") {
        Category::Dex
    } else if path.contains("oat") {
        Category::Oat
    } else if path.contains("jit") {
        Category::Jit
    } else if path.contains("lib") || path.ends_with(".so") || path.contains(".so.") {
        Category::Native
    } else if path.contains("kernel")
        || path.contains("[k")
        || symbol.starts_with("__")
        || symbol.starts_with("do_")
    {
        Category::Kernel
    } else if path.contains("perf_event") || path.contains("offcpu") {
        Category::OffCpu
    } else if path.contains("usr") || path.contains("bin") || path.contains("sbin") {
        Category::User
    } else {
        Category::Other
    }
}

#[derive(Debug)]
pub struct ProfileBuilder {
    pid: u32,
    interval: Duration,
    libs: Vec<Lib>,
    threads: HashMap<u32, ThreadBuilder>,
    start_time: Instant,
    start_time_system: SystemTime,
    // start_time: f64,       // as milliseconds since unix epoch
    end_time: Option<Instant>, // as milliseconds since start_time
    command_name: String,
    subprocesses: Vec<ProfileBuilder>,
}

#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct StringIndex(u32);

impl ProfileBuilder {
    pub fn new(
        start_time: Instant,
        start_time_system: SystemTime,
        command_name: &str,
        pid: u32,
        interval: Duration,
    ) -> Self {
        // let now_instant = Instant::now();
        // let now_system = SystemTime::now();
        // let duration_before_now = now_instant.duration_since(start_time);
        // let start_time_system = now_system - duration_before_now;
        // let duration_since_unix_epoch = start_time_system.duration_since(UNIX_EPOCH).unwrap();
        ProfileBuilder {
            pid,
            interval,
            threads: HashMap::new(),
            libs: Vec::new(),
            // start_time: duration_since_unix_epoch.as_secs_f64() * 1000.0,
            start_time,
            start_time_system,
            end_time: None,
            command_name: command_name.to_owned(),
            subprocesses: Vec::new(),
        }
    }

    pub fn set_start_time(&mut self, start_time: Instant) {
        self.start_time = start_time;
    }

    pub fn set_end_time(&mut self, end_time: Instant) {
        self.end_time = Some(end_time);
    }

    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    pub fn add_lib(
        &mut self,
        name: &str,
        path: &str,
        uuid: &Uuid,
        arch: &'static str,
        address_range: &std::ops::Range<u64>,
    ) {
        self.libs.push(Lib {
            name: name.to_string(),
            path: path.to_string(),
            arch,
            breakpad_id: format!("{:X}0", uuid.simple()),
            start_address: address_range.start,
            end_address: address_range.end,
        })
    }

    // pub fn add_sample(&mut self, thread_index: u32, timestamp: f64, frames: &[u64]) {
    //     let thread = self
    //         .threads
    //         .entry(thread_index)
    //         .or_insert_with(|| ThreadBuilder::new(thread_index, timestamp));
    //     thread.add_sample(timestamp, frames);
    // }

    pub fn add_thread(&mut self, thread_builder: ThreadBuilder) {
        self.threads.insert(thread_builder.index, thread_builder);
    }

    pub fn add_subprocess(&mut self, profile_builder: ProfileBuilder) {
        self.subprocesses.push(profile_builder);
    }

    fn collect_marker_schemas(&self) -> HashMap<&'static str, MarkerSchema> {
        let mut marker_schemas = HashMap::new();
        for thread in self.threads.values() {
            marker_schemas.extend(thread.marker_schemas.clone().into_iter());
        }
        for process in &self.subprocesses {
            marker_schemas.extend(process.collect_marker_schemas().into_iter());
        }
        marker_schemas
    }

    pub fn to_json(&self) -> serde_json::Value {
        let start_time_ms_since_unix_epoch = self
            .start_time_system
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            * 1000.0;

        let end_time_ms_since_start = self
            .end_time
            .map(|end_time| to_profile_timestamp(end_time, self.start_time));
        let mut sorted_threads: Vec<_> = self.threads.iter().collect();
        sorted_threads.sort_by(|(_, a), (_, b)| {
            if let Some(ordering) = a.get_start_time().partial_cmp(&b.get_start_time()) {
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            let ordering = a.get_name().cmp(&b.get_name());
            if ordering != Ordering::Equal {
                return ordering;
            }
            a.get_tid().cmp(&b.get_tid())
        });
        let threads: Vec<Value> = sorted_threads
            .into_iter()
            .map(|(_, thread)| thread.to_json(&self.command_name, self.start_time))
            .collect();
        let mut sorted_libs: Vec<_> = self.libs.iter().collect();
        sorted_libs.sort_by_key(|l| l.start_address);
        let libs: Vec<Value> = sorted_libs.iter().map(|l| l.to_json()).collect();

        let mut sorted_subprocesses: Vec<_> = self.subprocesses.iter().collect();
        sorted_subprocesses.sort_by(|a, b| {
            if let Some(ordering) = a.start_time.partial_cmp(&b.start_time) {
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            a.pid.cmp(&b.pid)
        });

        let subprocesses: Vec<Value> = sorted_subprocesses.iter().map(|p| p.to_json()).collect();
        let mut marker_schemas: Vec<MarkerSchema> =
            self.collect_marker_schemas().into_values().collect();
        marker_schemas.sort_by_key(|schema| schema.type_name);
        json!({
            "meta": {
                "version": 24,
                "startTime": start_time_ms_since_unix_epoch,
                "shutdownTime": end_time_ms_since_start,
                "pausedRanges": [],
                "product": self.command_name,
                "interval": self.interval.as_secs_f64() * 1000.0,
                "pid": self.pid,
                "processType": 0,
                "categories": all_categories_1(),
                "sampleUnits": {
                    "time": "ms",
                    "eventDelay": "ms",
                    "threadCPUDelta": "µs"
                },
                "markerSchema": marker_schemas,
            },
            "libs": libs,
            "threads": threads,
            "processes": subprocesses,
        })
    }
}

fn to_profile_timestamp(instant: Instant, process_start: Instant) -> f64 {
    (instant - process_start).as_secs_f64() * 1000.0
}

#[derive(Debug)]
pub struct ThreadBuilder {
    pid: u32,
    index: u32,
    name: Option<String>,
    start_time: Instant,
    end_time: Option<Instant>,
    is_main: bool,
    is_libdispatch_thread: bool,
    stack_table: StackTable,
    frame_table: FrameTable,
    samples: SampleTable,
    markers: MarkerTable,
    marker_schemas: HashMap<&'static str, MarkerSchema>,
    string_table: StringTable,
}

impl ThreadBuilder {
    pub fn new(
        pid: u32,
        thread_index: u32,
        start_time: Instant,
        is_main: bool,
        is_libdispatch_thread: bool,
    ) -> Self {
        ThreadBuilder {
            pid,
            index: thread_index,
            name: None,
            start_time,
            end_time: None,
            is_main,
            is_libdispatch_thread,
            stack_table: StackTable::new(),
            frame_table: FrameTable::new(),
            samples: SampleTable(Vec::new()),
            markers: MarkerTable::new(),
            marker_schemas: HashMap::new(),
            string_table: StringTable::new(),
        }
    }

    pub fn set_start_time(&mut self, start_time: Instant) {
        self.start_time = start_time;
    }

    pub fn get_start_time(&self) -> Instant {
        self.start_time
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = Some(name.to_owned());
    }

    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn get_tid(&self) -> u32 {
        self.index
    }

    pub fn handle_for_string(&mut self, s: &str) -> usize {
        self.string_table.index_for_string(s)
    }

    pub fn add_sample(
        &mut self,
        timestamp: f64,
        stack_frames: &[StackFrameInfo],
        cpu_delta: u64,
    ) -> Option<usize> {
        let stack_index = self.stack_index_for_frames(stack_frames);
        self.samples.0.push(Sample {
            timestamp,
            stack_index,
            cpu_delta,
        });
        stack_index
    }

    pub fn add_sample_same_stack(
        &mut self,
        timestamp: f64,
        previous_stack: Option<usize>,
        cpu_delta: u64,
    ) {
        self.samples.0.push(Sample {
            timestamp,
            stack_index: previous_stack,
            cpu_delta,
        });
    }

    /// Main marker API to add a new marker to profiler buffer.
    pub fn add_marker<T: ProfilerMarker>(
        &mut self,
        name: &str,
        marker: T,
        start_time: f64,
        end_time: f64,
    ) {
        self.marker_schemas
            .entry(T::MARKER_TYPE_NAME)
            .or_insert_with(T::schema);
        let name_string_index = self.string_table.index_for_string(name);
        self.markers.0.push(Marker {
            name_string_index,
            start_time,
            end_time,
            data: marker.json_marker_data(),
        })
    }

    pub fn notify_dead(&mut self, end_time: Instant) {
        self.end_time = Some(end_time);
    }

    fn stack_index_for_frames(&mut self, stack_frames: &[StackFrameInfo]) -> Option<usize> {
        let frame_indexes: Vec<_> = stack_frames
            .iter()
            .map(|f| self.frame_index_for_address(f))
            .collect();
        self.stack_table.index_for_frames(&frame_indexes)
    }

    fn frame_index_for_address(&mut self, frame: &StackFrameInfo) -> usize {
        self.frame_table
            .index_for_frame(&mut self.string_table, frame)
    }

    fn to_json(&self, process_name: &str, process_start: Instant) -> Value {
        let register_time = to_profile_timestamp(self.start_time, process_start);
        let unregister_time = self
            .end_time
            .map(|end_time| to_profile_timestamp(end_time, process_start));
        let name = if self.is_main {
            // https://github.com/firefox-devtools/profiler/issues/2508
            "GeckoMain".to_string()
        } else if let Some(name) = &self.name {
            name.clone()
        } else if self.is_libdispatch_thread {
            "libdispatch".to_string()
        } else {
            format!("Thread <{}>", self.index)
        };
        let markers = self.markers.to_json(process_start);
        json!({
            "name": name,
            "tid": self.index,
            "pid": self.pid,
            "processType": "default",
            "processName": process_name,
            "registerTime": register_time,
            "unregisterTime": unregister_time,
            "frameTable": self.frame_table.to_json(),
            "stackTable": self.stack_table.to_json(),
            "samples": self.samples.to_json(),
            "markers": markers,
            "stringTable": self.string_table.to_json()
        })
    }
}

#[derive(Debug)]
struct Lib {
    name: String,
    path: String,
    arch: &'static str,
    breakpad_id: String,
    start_address: u64,
    end_address: u64,
}

impl Lib {
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "debugName": self.name,
            "path": self.path,
            "debugPath": self.path,
            "breakpadId": self.breakpad_id,
            "offset": 0,
            "start": self.start_address,
            "end": self.end_address,
            "arch": self.arch,
        })
    }
}

#[derive(Debug)]
struct StackTable {
    // (parent stack, frame_index)
    stacks: Vec<(Option<usize>, usize)>,

    // (parent stack, frame_index) -> stack index
    index: BTreeMap<(Option<usize>, usize), usize>,
}

impl StackTable {
    pub fn new() -> StackTable {
        StackTable {
            stacks: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    pub fn index_for_frames(&mut self, frame_indexes: &[usize]) -> Option<usize> {
        let mut prefix = None;
        for &frame_index in frame_indexes {
            match self.index.get(&(prefix, frame_index)) {
                Some(stack_index) => {
                    prefix = Some(*stack_index);
                }
                None => {
                    let stack_index = self.stacks.len();
                    self.stacks.push((prefix, frame_index));
                    self.index.insert((prefix, frame_index), stack_index);
                    prefix = Some(stack_index);
                }
            }
        }
        prefix
    }

    pub fn to_json(&self) -> Value {
        let data: Vec<Value> = self
            .stacks
            .iter()
            .map(|(prefix, frame_index)| {
                let prefix = match prefix {
                    Some(prefix) => Value::Number((*prefix as u64).into()),
                    None => Value::Null,
                };
                json!([prefix, frame_index])
            })
            .collect();
        json!({
            "schema": {
                "prefix": 0,
                "frame": 1,
            },
            "data": data
        })
    }
}

#[derive(Debug)]
struct FrameTable {
    // [string_index]
    frames: Vec<(usize, Category, usize, usize, usize)>,

    // address -> frame index
    index: BTreeMap<String, usize>,
}

impl FrameTable {
    pub fn new() -> FrameTable {
        FrameTable {
            frames: Vec::new(),
            index: BTreeMap::new(),
        }
    }

    pub fn index_for_frame(
        &mut self,
        string_table: &mut StringTable,
        frame: &StackFrameInfo,
    ) -> usize {
        let frames = &mut self.frames;
        *self.index.entry(frame.id.clone()).or_insert_with(|| {
            let frame_index = frames.len();
            let location_string = frame.fmt_symbol();

            // find symbol category to determine color
            let obj_path = if frame.object_path().is_some() {
                frame.object_path().unwrap().to_str().unwrap()
            } else {
                "unknown"
            };
            let symbol = if frame.symbol.is_some() {
                frame.symbol.as_ref().unwrap().as_str()
            } else {
                frame.fmt_object()
            };
            let category = categorize_frame(obj_path, symbol);

            let location_string_index = string_table.index_for_string(&location_string);

            let file = if frame.file.is_some() {
                frame.file.as_ref().unwrap().as_str()
            } else {
                "unknown"
            };
            let file_idx = string_table.index_for_string(file);

            let line = if frame.line.is_some() {
                frame.line.unwrap().to_string()
            } else {
                "unknown".to_string()
            };
            let line_idx = string_table.index_for_string(&line);

            let col = if frame.col.is_some() {
                frame.col.unwrap().to_string()
            } else {
                "unknown".to_string()
            };
            let col_idx = string_table.index_for_string(&col);

            frames.push((location_string_index, category, file_idx, line_idx, col_idx));
            frame_index
        })
    }

    pub fn to_json(&self) -> Value {
        let data: Vec<Value> = self
            .frames
            .iter()
            .map(|(location, category, file, line, col)| {
                let inner_window_id = 0;
                let subcategory = 0;
                json!([
                    *location,
                    false,
                    inner_window_id,
                    null,
                    file,
                    line,
                    col,
                    null,
                    *category as u8,
                    subcategory
                ])
            })
            .collect();
        json!({
            "schema": {
                "category": 8,
                "column": 6,
                "file": 4,
                "implementation": 3,
                "innerWindowID": 2,
                "line": 5,
                "location": 0,
                "optimizations": 7,
                "relevantForJS": 1,
                "subcategory": 9
            },
            "data": data
        })
    }
}

#[derive(Debug)]
struct SampleTable(Vec<Sample>);

impl SampleTable {
    pub fn to_json(&self) -> Value {
        let data: Vec<Value> = self
            .0
            .iter()
            .map(|sample| json!([sample.stack_index, sample.timestamp, 0.0, sample.cpu_delta]))
            .collect();
        json!({
            "schema": {
                "stack": 0,
                "time": 1,
                "eventDelay": 2,
                "threadCPUDelta": 3
            },
            "data": data
        })
    }
}

#[derive(Debug)]
struct Sample {
    timestamp: f64,
    stack_index: Option<usize>,
    cpu_delta: u64,
}

#[derive(Debug)]
struct StringTable {
    strings: Vec<String>,
    index: HashMap<String, usize>,
}

impl StringTable {
    pub fn new() -> Self {
        StringTable {
            strings: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub fn index_for_string(&mut self, s: &str) -> usize {
        *self.index.entry(s.to_string()).or_insert_with(|| {
            let idx = self.strings.len();
            self.strings.push(s.to_string());
            idx
        })
    }

    pub fn to_json(&self) -> Value {
        Value::Array(
            self.strings
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        )
    }
}

#[repr(u8)]
enum Phase {
    Instant = 0,
    Interval = 1,
    IntervalStart = 2,
    IntervalEnd = 3,
}

struct MarkerTableDataValue<'a> {
    name_string_index: usize,
    start: f64,
    end: f64,
    phase: u8,
    data: &'a Value,
}

#[derive(Debug, Clone)]
struct Marker {
    name_string_index: usize,
    start_time: f64,
    end_time: f64,
    data: Value,
}

impl Marker {
    fn to_json(&self) -> Value {
        json!([
            self.name_string_index,
            self.start_time,
            self.end_time,
            Phase::Interval as u8,
            &0,
            &self.data
        ])
    }
}

#[derive(Debug)]
struct MarkerTable(Vec<Marker>);

impl MarkerTable {
    fn new() -> Self {
        Self(Vec::new())
    }

    pub fn to_json(&self, process_start: Instant) -> Value {
        let data: Vec<Value> = self.0.iter().map(|m| m.to_json()).collect();
        json!({
            "schema": {
                "name": 0,
                "startTime": 1,
                "endTime": 2,
                "phase": 3,
                "category": 4,
                "data": 5,
            },
            "data": data
        })
    }
}
