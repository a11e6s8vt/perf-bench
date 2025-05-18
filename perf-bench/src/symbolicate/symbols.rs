use crate::StackInfo;
use anyhow::Context as _;
use anyhow::Result;
use aya::maps::{MapData, StackTraceMap};
use aya::{maps::stack_trace::StackTrace, util::kernel_symbols};
use proc_maps::MapRange;
use rustc_demangle::demangle;

use blazesym::symbolize::source::Elf;
use blazesym::symbolize::source::Source;
use blazesym::symbolize::CodeInfo;
use blazesym::symbolize::Input;
use blazesym::symbolize::Sym;
use blazesym::symbolize::Symbolized;
use blazesym::symbolize::Symbolizer;
use blazesym::Addr;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const ADDR_WIDTH: usize = 16;

/// converts pointers from bpf to usable, symbol resolved stack information
pub fn symbolicate_stack_trace(
    stack_info: &StackInfo,
    stack_traces: &StackTraceMap<MapData>,
    map_ranges: Option<&[MapRange]>,
) -> Vec<StackFrameInfo> {
    let ktrace_id = stack_info.kernel_stack_id;
    let utrace_id = stack_info.user_stack_id;

    if stack_info.tid == 0 {
        let mut idle = StackFrameInfo::prepare(stack_info);
        idle.symbol = Some("idle".into());
        let mut idle_cpu = StackFrameInfo::process_only(stack_info);

        idle_cpu.symbol = idle_cpu.symbol.map(|s| s.replace("swapper/", "cpu_"));

        return vec![idle, idle_cpu];
    }

    let kernel_stack = if ktrace_id > -1 {
        stack_traces.get(&(ktrace_id as u32), 0).ok()
    } else {
        None
    };

    let user_stack = if utrace_id > -1 {
        stack_traces.get(&(utrace_id as u32), 0).ok()
    } else {
        None
    };

    let mut combined = resolve_stack_trace(kernel_stack, user_stack, stack_info, map_ranges);
    if stack_info.pid == Some(stack_info.tid) {
        let pid_info = StackFrameInfo::process_only(stack_info);
        combined.push(pid_info);
    }
    combined.reverse();

    combined
}

fn resolve_stack_trace(
    kernel_stack: Option<StackTrace>,
    user_stack: Option<StackTrace>,
    meta: &StackInfo,
    map_ranges: Option<&[MapRange]>,
) -> Vec<StackFrameInfo> {
    let kernel_stacks = kernel_stack.map(|trace| resolve_kernel_trace(&trace, meta));
    let user_stacks = user_stack.map(|trace| resolve_user_trace(&trace, meta, map_ranges.unwrap()));

    match (kernel_stacks, user_stacks) {
        (Some(kernel_stacks), None) => kernel_stacks,
        (None, Some(user_stacks)) => user_stacks.into_iter().flatten().collect(),
        (Some(kernel_stacks), Some(user_stacks)) => kernel_stacks
            .into_iter()
            .chain(
                user_stacks
                    .into_iter()
                    .flatten()
                    .collect::<Vec<StackFrameInfo>>(),
            )
            .collect::<Vec<_>>(),
        _ => Default::default(),
    }
}

/// Resolves user space stack trace
fn resolve_user_trace(
    trace: &StackTrace,
    meta: &StackInfo,
    map_ranges: &[MapRange],
) -> Vec<Vec<StackFrameInfo>> {
    let user_stack = trace
        .frames()
        .iter()
        .filter_map(|frame| {
            if is_a_valid_addr(frame.ip) {
                let map = map_ranges.iter().find(|m| {
                    frame.ip >= m.start() as u64 && frame.ip <= m.start() as u64 + m.size() as u64
                })?;
                let binary_path = map.filename().unwrap_or_else(|| Path::new("")).to_owned();
                let load_address = map.start();
                let relative_ip = frame.ip - load_address as u64;
                let path = binary_path.to_str().unwrap_or_default();
                if path == "[vdso]" || path.starts_with('[') {
                    // since this is a cache entry, should prevent much reloading
                    return None;
                }

                resolve(meta, frame.ip, relative_ip, binary_path).ok()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    user_stack
}

fn is_a_valid_addr(ip: u64) -> bool {
    match ip {
        0..=0x0000_7FFF_FFFF_FFFF => {
            // "User space"
            true
        }
        0xFFFF_8000_0000_0000..=0xFFFF_FFFF_FFFF_FFFE => {
            // "Kernel space"
            true
        }
        0xFFFF_FFFF_FFFF_FFFF => {
            // "Invalid (bogus / EFAULT)"
            false
        }
        _ => {
            // "Non-canonical / reserved"
            false
        }
    }
}

/// takes an Aya StackTrace contain StackFrames into our StackFrameInfo struct
fn resolve_kernel_trace(trace: &StackTrace, meta: &StackInfo) -> Vec<StackFrameInfo> {
    let ksyms = kernel_symbols().unwrap();
    let kernel_stack = trace
        .frames()
        .iter()
        .map(|frame| {
            let mut info = StackFrameInfo::prepare(meta);
            if let Some(sym) = ksyms.range(..=frame.ip).next_back().map(|(_, s)| s) {
                info.symbol = Some(format!("{sym}_[k]"));
                info.file = Some("/proc/kallsyms".to_string());
                info.object_path = Some(PathBuf::from("/proc/kallsyms"));
                info.address = frame.ip;
                // println!("{:#x} {}", frame.ip, sym);
            } else {
                // println!("{:#x}", frame.ip);
            }
            info
        })
        .collect::<Vec<_>>();
    kernel_stack
}

/// Based on virtual address calculated from proc maps, resolve symbols
fn resolve(
    meta: &StackInfo,
    virtual_address: u64,
    relative_address: u64,
    bin_path: PathBuf,
) -> Result<Vec<StackFrameInfo>, anyhow::Error> {
    let mut sym_stackframes: Vec<StackFrameInfo> = Vec::new();

    let src = Source::Elf(Elf::new(&bin_path));
    let addrs = [relative_address];
    let symbolizer = Symbolizer::builder()
        .enable_code_info(true)
        .enable_demangling(true)
        .enable_inlined_fns(true)
        .build();
    let syms = symbolizer
        .symbolize(&src, Input::VirtOffset(&addrs))
        .with_context(|| format!("failed to symbolize address {relative_address:#x}"))?;

    let mut file = File::open(&bin_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let obj_file = object::File::parse(&*buffer)?;
    let mut func_address_map: Vec<(String, u64)> = Vec::new();

    for (i, (input_addr, sym)) in addrs.iter().copied().zip(syms).enumerate() {
        match sym {
            Symbolized::Sym(Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                let demangled = remove_generics(demangle(&name).to_string());
                // println!("{:?}", &demangled);
                let loc = print_frame(&demangled, Some((input_addr, addr, offset)), &code_info);
                let mut info = StackFrameInfo::prepare(meta);
                info.id = format!("{virtual_address}-{i}");
                info.address = virtual_address;
                info.object_path = Some(bin_path.clone());
                info.symbol = Some(demangled);
                if let Some(loc) = loc {
                    info.file = loc.0;
                    info.line = loc.1;
                    info.col = loc.2;
                }

                sym_stackframes.push(info);

                for (j, frame) in inlined.iter().enumerate() {
                    let demangled = remove_generics(demangle(&frame.name).to_string());
                    // println!("    {:?}", &demangled);
                    let loc = print_frame(&demangled, None, &frame.code_info);
                    let mut inner_info = StackFrameInfo::prepare(meta);
                    inner_info.id = format!("{virtual_address}-{i}-{j}");
                    inner_info.address = virtual_address;
                    inner_info.object_path = Some(bin_path.clone());
                    inner_info.symbol = Some(demangled);
                    if let Some(loc) = loc {
                        inner_info.file = loc.0;
                        inner_info.line = loc.1;
                        inner_info.col = loc.2;
                    }

                    sym_stackframes.push(inner_info);
                }
            }
            Symbolized::Unknown(..) => {
                let mut info = StackFrameInfo::prepare(meta);
                info.address = virtual_address;
                info.object_path = Some(bin_path.clone());
                info.symbol = Some(format!("{input_addr:#0ADDR_WIDTH$x}: <no-symbol>"));
                sym_stackframes.push(info);
            }
        }
    }
    Ok(sym_stackframes)
}
/// Struct to contain information about a userspace/kernel stack frame
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct StackFrameInfo {
    pub id: String,
    pub pid: usize,
    pub name: String,

    /// Virtual memory address (absolute)
    pub address: u64,
    /// Shared Object / Module
    pub object_path: Option<PathBuf>,

    /// Source file and location
    pub symbol: Option<String>,

    /// Source file
    pub file: Option<String>,

    /// line no
    pub line: Option<u32>,

    /// column no
    pub col: Option<u16>,
}

impl StackFrameInfo {
    /// Creates an empty/default StackFrameInfo
    pub fn prepare(meta: &StackInfo) -> Self {
        Self {
            pid: meta.tid as usize,
            // "".to_string(), // don't really need meta.get_cmd(),
            ..Default::default()
        }
    }

    /// Creates an StackFrameInfo placeholder for process name
    pub fn process_only(meta: &StackInfo) -> Self {
        let name = meta.name.clone();
        let with_pid = false;

        let sym = if with_pid {
            format!("{} ({})", name, meta.tid)
        } else {
            name.to_owned()
        };

        Self {
            pid: meta.tid as usize,
            name,
            symbol: Some(sym),
            ..Default::default()
        }
    }

    pub fn new(address: u64, object_path: Option<PathBuf>) -> Self {
        Self {
            address,
            object_path,
            ..Default::default()
        }
    }

    /// Physical memory address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }

    pub fn fmt(&self) -> String {
        format!(
            "{:#x}\t{}\t{}\t{}",
            self.address(),
            self.name,
            self.fmt_object(),
            self.fmt_symbol()
        )
    }

    pub fn fmt_symbol(&self) -> String {
        format!(
            "{}@{}:{}:{}",
            self.symbol.as_deref().unwrap_or(
                //"[unknown]"
                format!("{}+{:#x}", self.fmt_object(), self.address).as_str(),
            ),
            self.fmt_file(),
            self.fmt_line(),
            self.fmt_col()
        )
    }

    pub fn fmt_object(&self) -> &str {
        self.object_path()
            .and_then(|v| v.file_name())
            .and_then(|v| v.to_str())
            .unwrap_or(&self.name)
    }

    fn fmt_shorter_source(&self, count: usize) -> Option<String> {
        StackFrameInfo::fmt_shorter(self.file.as_deref(), count)
    }

    /// instead of bla/meh/mah/test.c
    /// returns mah/test.c for example
    fn fmt_shorter(op: Option<&str>, count: usize) -> Option<String> {
        op.map(|v| {
            v.split('/')
                .rev()
                .take(count)
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .into_iter()
                .rev()
                .collect::<Vec<String>>()
                .join("/")
        })
    }

    pub fn fmt_file(&self) -> String {
        // let short = self.source.as_deref();
        // .and_then(|v| {
        //     let s = v.split('/');
        //     s.last()
        // });

        // let short = self.fmt_shorter_source(4);

        if self.file.is_some() {
            format!(" ({})", self.file.as_ref().unwrap())
        } else {
            "".to_string()
        }
    }
    pub fn fmt_line(&self) -> String {
        // let short = self.source.as_deref();
        // .and_then(|v| {
        //     let s = v.split('/');
        //     s.last()
        // });

        // let short = self.fmt_shorter_source(4);

        if self.line.is_some() {
            format!(" ({})", self.line.as_ref().unwrap())
        } else {
            "".to_string()
        }
    }

    pub fn fmt_col(&self) -> String {
        // let short = self.source.as_deref();
        // .and_then(|v| {
        //     let s = v.split('/');
        //     s.last()
        // });

        // let short = self.fmt_shorter_source(4);

        if self.col.is_some() {
            format!(" ({})", self.col.as_ref().unwrap())
        } else {
            "".to_string()
        }
    }
}

fn remove_generics(mut func: String) -> String {
    func = func.replace(';', ":");
    let mut bracket_depth = 0;

    let mut new_str = String::with_capacity(func.len());
    let mut continous_seperator = 0;
    let mut running = false;

    for (_idx, c) in func.char_indices() {
        match c {
            '<' => {
                bracket_depth += 1;
            }
            '>' => {
                bracket_depth -= 1;
            }
            ':' => {
                if bracket_depth > 0 {
                    continue;
                }

                continous_seperator += 1;

                if continous_seperator <= 2 && running {
                    new_str.push(c);
                }
            }
            _ => {
                if bracket_depth > 0 {
                    continue;
                }
                continous_seperator = 0;
                new_str.push(c);
                running = true;
            }
        };
    }

    new_str
}

fn print_frame(
    name: &str,
    addr_info: Option<(Addr, Addr, usize)>,
    code_info: &Option<CodeInfo>,
) -> Option<(Option<String>, Option<u32>, Option<u16>)> {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path: String = format!("{}", path.display());

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => (Some(path), Some(line), Some(col)),
            (Some(line), None) => (Some(path), Some(line), None),
            (None, _) => (Some(path), None, None),
        }
    });

    code_info
}

#[test]
fn test_clean() {
    let tests = [
        "<<lock_api::rwlock::RwLock<R,T> as core::fmt::Debug>::fmt::LockedPlaceholder as core::fmt::Debug>::fmt",
        "core::array::<impl core::ops::index::IndexMut<I> for [T: N]>::index_mut",
        "alloc::collections::btree::search::<impl alloc::collections::btree::node::NodeRef<BorrowType,K,V,alloc::collections::btree::node::marker::LeafOrInternal>>::search_tree",
        "alloc::collections::btree::node::Handle<alloc::collections::btree::node::NodeRef<BorrowType,K,V,alloc::collections::btree::node::marker::Internal>,alloc::collections::btree::node::marker::Edge>::descend",
        "alloc::collections::btree::node::NodeRef<alloc::collections::btree::node::marker::Immut,K,V,Type>::keys",
        "core::ptr::drop_in_place<gimli::read::line::LineInstruction<gimli::read::endian_reader::EndianReader<gimli::endianity::RunTimeEndian,alloc::rc::Rc<[u8]>>,usize>>",
        "<core::iter::adapters::enumerate::Enumerate<I> as core::iter::traits::iterator::Iterator>::next",
    ];

    let expected = [
        "fmt",
        "core::array::index_mut",
        "alloc::collections::btree::search::search_tree",
        "alloc::collections::btree::node::Handle::descend",
        "alloc::collections::btree::node::NodeRef::keys",
        "core::ptr::drop_in_place",
        "next",
    ];

    for no in 0..tests.len() {
        assert_eq!(remove_generics(tests[no].to_string()), expected[no]);
    }
}
pub fn symbolicate() {}
