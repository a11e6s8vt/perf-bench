# perf-bench

## Prerequisites

```shell
aya-tool generate bpf_perf_event_data trace_event_raw_sched_switch task_struct > perf-bench-ebpf/src/bindings.rs
```

### CPU Sampling Results

```json
[
    {
        1675: Thread { tid: 1675, pid: Some(1675), name: None,
            samples: [
                Sample2 { timestamp: 15917450217003, cpu_delta: 509676, stack_id: 107648, on_cpu: true }
            ]
        },
        9480: Thread { tid: 9480, pid: None, name: None,
            samples: [
                Sample2 { timestamp: 15918073349151, cpu_delta: 24796, stack_id: 81899, on_cpu: false },
                Sample2 { timestamp: 15918074349151, cpu_delta: 0, stack_id: 81899, on_cpu: false },
                Sample2 { timestamp: 15918075349151, cpu_delta: 0, stack_id: 81899, on_cpu: false },
                Sample2 { timestamp: 15918076349151, cpu_delta: 0, stack_id: 81899, on_cpu: false },
                Sample2 { timestamp: 15918077349151, cpu_delta: 0, stack_id: 81899, on_cpu: false },
                Sample2 { timestamp: 15918078349151, cpu_delta: 0, stack_id: 81899, on_cpu: false },
            ]
        },
    },
    {
        12660: Thread { tid: 12660, pid: None, name: None,
            samples: [
                Sample2 { timestamp: 8376110318862, cpu_delta: 451254, stack_id: 7835, on_cpu: false },
                Sample2 { timestamp: 8376111318862, cpu_delta: 0, stack_id: 7835, on_cpu: false },
                Sample2 { timestamp: 8376112318862, cpu_delta: 0, stack_id: 7835, on_cpu: false },
                Sample2 { timestamp: 8376113318862, cpu_delta: 0, stack_id: 7835, on_cpu: false },
                Sample2 { timestamp: 8376114318862, cpu_delta: 0, stack_id: 7835, on_cpu: false },
            ]
        },
        1818: Thread {
          tid: 1818, pid: None, name: None,
          samples: [
            Sample2 { timestamp: 8375445790608, cpu_delta: 135783, stack_id: 81012, on_cpu: false },
            Sample2 { timestamp: 8375446790608, cpu_delta: 0, stack_id: 81012, on_cpu: false },
            Sample2 { timestamp: 8375447790608, cpu_delta: 0, stack_id: 81012, on_cpu: false },
            Sample2 { timestamp: 8375448790608, cpu_delta: 0, stack_id: 81012, on_cpu: false },
          ]
        },
    },
    {
        1798: Thread {
          tid: 1798, pid: None, name: None,
          samples: [
            Sample2 { timestamp: 8376112952048, cpu_delta: 40426, stack_id: 112094, on_cpu: false },
            Sample2 { timestamp: 8376113952048, cpu_delta: 0, stack_id: 112094, on_cpu: false },
            Sample2 { timestamp: 8376114952048, cpu_delta: 0, stack_id: 112094, on_cpu: false },
            Sample2 { timestamp: 8376115952048, cpu_delta: 0, stack_id: 112094, on_cpu: false },
            Sample2 { timestamp: 8376116952048, cpu_delta: 0, stack_id: 112094, on_cpu: false },
            Sample2 { timestamp: 8376117952048, cpu_delta: 0, stack_id: 112094, on_cpu: false },
          ]
        }
    }
]
```
