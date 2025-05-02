use crate::cache::PointerStackFramesCache;
use crate::symbols::{StackFrameInfo, SymbolFinder};
use crate::StackInfo;
use aya::maps::{MapData, StackTraceMap};

/// Profile library to track, lookup and cache stacktraces
pub struct Profiler {
    symbols: SymbolFinder,
    cache: PointerStackFramesCache,
}

impl Profiler {
    pub fn new() -> Self {
        Profiler {
            symbols: SymbolFinder::new(true),
            cache: Default::default(),
        }
    }

    pub fn print_stats(&self) {
        println!("{}", self.symbols.process_cache.stats());
        println!("{}", self.symbols.addr_cache.stats());
        println!("{}", self.cache.stats());
    }

    pub fn get_stack(
        &mut self,
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
    ) -> Vec<StackFrameInfo> {
        // if let Some(stacks) = self.cache.get(ktrace_id, utrace_id) {
        //     return stacks;
        // }

        Self::format_stack_trace(stack_info, stack_traces, &mut self.symbols)
    }

    /// converts pointers from bpf to usable, symbol resolved stack information
    fn format_stack_trace(
        stack_info: &StackInfo,
        stack_traces: &StackTraceMap<MapData>,
        symbols: &mut SymbolFinder,
    ) -> Vec<StackFrameInfo> {
        let ktrace_id = stack_info.kernel_stack_id;
        let utrace_id = stack_info.user_stack_id;

        if stack_info.tid == 0 {
            let mut idle = StackFrameInfo::prepare(stack_info);
            idle.symbol = Some("idle".into());
            let mut idle_cpu = StackFrameInfo::process_only(stack_info);

            // if let Some(cpu_id) = stack_info.get_cpu_id() {
            //     idle_cpu.symbol = Some(format!("cpu_{:02}", cpu_id));
            // } else {
            idle_cpu.symbol = idle_cpu.symbol.map(|s| s.replace("swapper/", "cpu_"));
            // }

            // if group_by_cpu {
            //     if let Some(cpu_id) = stack_info.get_cpu_id() {
            //         idle_cpu.symbol = Some(format!("cpu_{:02}", cpu_id));
            //         return vec![idle_cpu, idle];
            //     }
            // }

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

        let mut combined = symbols.resolve_stack_trace(kernel_stack, user_stack, stack_info);
        let pid_info = StackFrameInfo::process_only(stack_info);
        combined.push(pid_info);

        // if group_by_cpu {
        //     if let Some(cpu_id) = stack_info.get_cpu_id() {
        //         let frame = StackFrameInfo {
        //             symbol: Some(format!("cpu_{:02}", cpu_id)),
        //             ..Default::default()
        //         };
        //
        //         combined.push(frame);
        //     }
        // }

        combined.reverse();

        combined
    }
}
