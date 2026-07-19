# xprobe：面向人类与 Coding Agent 的运行时跨域延迟探针

## 1. 项目定位

`xprobe` 是一个用于测量 Linux Host 事件与 GPU Device 事件之间精确时间关系的运行时探针。

它面向两类一等用户：

1. 性能工程师和服务开发者。
2. Claude Code、Codex CLI、Codex App、Cursor 等 coding agent。

`xprobe` 本身不是 Agent，不接入任何模型 API，不理解自然语言，也不实现自主规划循环。

系统职责边界为：

```text
人类或 Coding Agent
    负责理解问题、阅读代码、选择观测事件、解释结果

xprobe
    负责发现能力、校验配置、附加探针、采集事件、关联时间线、
    计算延迟、报告数据质量并清理资源
```

项目核心原则：

```text
Agent decides.
xprobe validates.
xprobe measures.
Agent interprets.
```

## 2. 项目目标

构建一个可以在尽量不修改业务代码、不重新编译业务程序的情况下，对运行中服务进行局部、精确、低开销测量的工具。

用户可以定义两个或多个事件点，例如：

```text
Host 函数进入
CUDA Runtime API 进入或返回
CUDA Driver API 进入或返回
GPU kernel 开始或结束
GPU memcpy 开始或结束
线程被唤醒或切出
系统调用进入或返回
```

然后测量：

```text
event B timestamp - event A timestamp
```

典型问题包括：

```text
handle_request 进入后多久调用 cudaLaunchKernel？
cudaLaunchKernel 返回后多久 kernel 才真正开始执行？
两个 kernel 之间为什么存在 3 ms 空洞？
HTTP 请求进入服务后多久开始第一个 GPU 操作？
GPU kernel 完成后多久返回业务线程？
某次 CUDA 同步调用究竟阻塞了多久？
某个长尾是 Host 调度、CUDA Runtime、GPU 排队还是 GPU 执行导致的？
```

`xprobe` 不以完整替代 Nsight Systems 为目标，而是提供：

```text
动态附着
局部观测
按需启用
事件级测量
结构化结果
低运行开销
容易被 Agent 操作
```

的运行时测量能力。

---

# 3. 非目标

`xprobe` 第一阶段不负责：

* 调用语言模型。
* 理解自然语言。
* 自动选择需要观测的函数或 kernel。
* 自主修改业务代码。
* 自动生成最终性能结论。
* 维护多轮对话状态。
* 提供 MCP Server。
* 提供独立的 Agent 服务。
* 实现完整分布式追踪系统。
* 完整替代 Nsight Systems 或 Nsight Compute。
* GPU 指令级追踪。
* 自动推断没有关联信息的跨线程业务因果关系。
* 默认向运行中进程注入共享库。
* 第一阶段支持 AMD ROCm、Windows 或 macOS。

---

# 4. Agent-friendly 的定义

`xprobe` 对 Agent 友好，不意味着它本身具有智能，而意味着它具备以下确定性接口特征。

## 4.1 所有主要操作都能非交互执行

任何命令都不得在非交互模式中等待：

```text
Do you want to continue? [y/N]
Please select a process
Press Enter to stop
```

所有模糊情况都必须返回结构化错误和候选项。

例如：

```json
{
  "ok": false,
  "error": {
    "code": "AMBIGUOUS_TARGET",
    "message": "Multiple target processes matched.",
    "candidates": [
      {
        "pid": 1234,
        "command": "/srv/app/server"
      },
      {
        "pid": 5678,
        "command": "/srv/app/server"
      }
    ]
  }
}
```

## 4.2 所有主要命令支持 JSON

统一形式：

```bash
xprobe <command> --json
```

要求：

* `stdout` 只包含最终机器结果。
* 日志输出到 `stderr`。
* JSON Schema 稳定且版本化。
* 不混入进度条、颜色控制符或解释性文本。
* 支持 `--no-color`。
* 支持 `--non-interactive`。
* 错误也必须输出合法 JSON。

## 4.3 发现、校验和执行分离

Agent 应能够先检查环境和配置，再执行高权限操作。

推荐流程：

```text
doctor
→ inspect
→ discover / resolve
→ validate
→ measure
→ inspect result
→ cleanup
```

`validate` 只做确定性检查，不进行智能规划。

## 4.4 错误可恢复

错误必须包含：

```text
稳定错误码
错误原因
是否可恢复
相关上下文
可能的确定性处理方式
```

例如：

```json
{
  "ok": false,
  "error": {
    "code": "CUPTI_AGENT_NOT_LOADED",
    "message": "GPU activity collection is unavailable for this process.",
    "recoverable": true,
    "details": {
      "pid": 1234,
      "host_probes_available": true,
      "gpu_activity_available": false
    }
  }
}
```

`xprobe` 可以报告可用能力，但不应自行决定是否重启服务、修改启动参数或降级测量目标。

## 4.5 输出证据而非自由文本结论

`xprobe` 应输出：

```text
测量样本
统计值
关联方式
关联置信度
未匹配事件
丢失事件
时钟来源
估计误差
原始 trace 引用
```

性能含义由人类或 Agent 解释。

---

# 5. 仓库结构

推荐仓库：

```text
xprobe/
├── README.md
├── AGENTS.md
├── LICENSE
├── Cargo.toml
├── CMakeLists.txt
├── justfile
│
├── xprobe/
│   ├── cli/
│   ├── core/
│   ├── collector/
│   ├── correlator/
│   ├── exporter/
│   ├── protocol/
│   └── daemon/
│
├── bpf/
│   ├── xprobe.bpf.c
│   ├── probes/
│   └── include/
│
├── cupti/
│   ├── include/
│   ├── src/
│   └── CMakeLists.txt
│
├── skills/
│   ├── xprobe-measure-latency/
│   │   ├── SKILL.md
│   │   ├── references/
│   │   ├── examples/
│   │   └── scripts/
│   │
│   ├── xprobe-debug-gpu-gap/
│   │   ├── SKILL.md
│   │   ├── references/
│   │   └── examples/
│   │
│   └── xprobe-development/
│       ├── SKILL.md
│       ├── references/
│       └── scripts/
│
├── schemas/
│   ├── event.schema.json
│   ├── error.schema.json
│   ├── measurement-spec.schema.json
│   ├── measurement-result.schema.json
│   └── capability.schema.json
│
├── docs/
│   ├── architecture.md
│   ├── event-model.md
│   ├── cli-contract.md
│   ├── clock-model.md
│   ├── security.md
│   └── compatibility.md
│
├── examples/
│   ├── vector-add/
│   ├── request-to-kernel/
│   └── kernel-gap/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── precision/
│   ├── overhead/
│   └── agent-contract/
│
└── benchmarks/
```

这里的 `skills/` 是仓库和发行包的一部分，而不是独立的 `xprobe-skill` 项目。

人类可以阅读其中的工作流和示例；支持 Agent Skills 的 coding agent 可以直接加载；不原生支持 Skills 的 Agent 也可以将其作为普通 Markdown 使用。

---

# 6. Skills 的定位

Skills 只提供任务方法和操作知识，不提供执行服务。

Skill 不调用模型 API，也不要求 `xprobe` 内置任何 Agent runtime。

## 6.1 建议的 Skills

### `xprobe-measure-latency`

用于：

```text
测量 Host 函数到 CUDA API 的延迟
测量 CUDA API 到 GPU kernel start 的延迟
测量 kernel end 到 Host 事件的延迟
测量任意两个已支持事件之间的时间差
```

### `xprobe-debug-gpu-gap`

用于：

```text
定位 kernel 间空洞
判断空洞来自 Host、Runtime、排队还是依赖关系
逐步扩大观测范围
```

### `xprobe-development`

用于开发 `xprobe` 本身：

```text
修改 eBPF probe
新增 CUPTI activity
扩展事件 Schema
运行 verifier、精度和开销测试
```

## 6.2 Skill 结构

例如：

```text
skills/xprobe-measure-latency/
├── SKILL.md
├── references/
│   ├── event-selectors.md
│   ├── correlation.md
│   ├── errors.md
│   └── safety.md
├── examples/
│   ├── host-to-launch.yaml
│   ├── launch-to-kernel.yaml
│   └── request-to-first-kernel.yaml
└── scripts/
    └── verify-result.py
```

`SKILL.md` 应保持较短，只描述：

* 何时使用该 Skill。
* 推荐操作顺序。
* 如何判断结果质量。
* 哪些行为禁止自动执行。
* 需要时读取哪些参考文件。

详细内容按需放入 `references/`，避免一次性占用大量上下文。

## 6.3 Skill 示例

```yaml
---
name: xprobe-measure-latency
description: Measure latency between Linux host events, CUDA API calls, GPU kernels, memory copies, and synchronization events using the xprobe CLI. Use for request-to-GPU latency, CUDA launch delay, GPU queueing delay, and cross-domain runtime measurements.
---
```

核心流程：

```text
1. Run `xprobe doctor --json`.
2. Inspect the target with `xprobe inspect --pid <pid> --json`.
3. Discover or resolve both event selectors.
4. Run `xprobe validate` before attaching probes.
5. Execute a bounded measurement by duration or sample count.
6. Check dropped events, unmatched events, timestamp error, and correlation method.
7. Stop or verify cleanup of every active session.
8. Base conclusions only on returned evidence.
```

## 6.4 Skills 不负责

* 自然语言转配置的具体实现。
* 调用某家模型。
* 长期保存用户偏好。
* 自动执行危险注入。
* 绕过 coding agent 自身的权限确认。
* 替代 CLI 文档和 JSON Schema。

---

# 7. 跨 Agent 兼容策略

`xprobe` 不为 Claude Code、Codex、Cursor 分别实现一套运行逻辑。

共同基础是：

```text
Shell
+ CLI
+ JSON
+ JSON Schema
+ Markdown Skills
```

Claude Code、Codex CLI、Codex App 和 Cursor 均可通过 shell 操作 `xprobe`。平台特定文件只作为极薄入口，不包含独立逻辑。

## 7.1 `AGENTS.md`

仓库根目录提供 `AGENTS.md`，用于 coding agent 开发 `xprobe` 本身时读取。

内容只包括长期工程规则：

```markdown
# xprobe engineering rules

- Run `just test` after changing Rust code.
- Run `just test-bpf` after changing files under `bpf/`.
- Run `just test-cupti` after changing files under `cupti/`.
- Never perform blocking I/O inside a CUPTI callback.
- Never perform symbol resolution inside an eBPF hot path.
- Never collect pointer-referenced user data by default.
- Never describe heuristic correlation as exact causality.
- Do not implement runtime process injection without a separately approved design.
- Every attach path must have cleanup and failure-recovery tests.
```

## 7.2 Claude Code

`CLAUDE.md` 直接指向 `@AGENTS.md`

## 7.3 Codex CLI 和 Codex App

Codex 可以：

* 读取 `AGENTS.md`。
* 加载或阅读 `skills/`。
* 执行 shell 命令。
* 解析 JSON 结果。

项目无需区分 Codex CLI 与 Codex App 的业务接口。

当执行环境不具备本地 GPU、root 权限或目标 PID 可见性时，`xprobe doctor --json` 应准确报告能力缺失，而不是由 Skill 假设执行环境。


# 9. 运行模式

## 9.1 一次性前台测量

默认模式：

```bash
xprobe measure ...
```

生命周期：

```text
启动 xprobe
→ 校验目标
→ 附加探针
→ 收集指定时长或样本数
→ 输出结果
→ 分离探针
→ 退出
```

这是首个版本优先支持的模式。

优点：

* 状态简单。
* 容易调试。
* 命令结束即完成清理。
* 适合 Agent 调用。
* 不需要长期运行服务。

## 9.2 后台会话

对于较长采集，可以支持：

```bash
xprobe measure ... --detach
```

返回会话 ID：

```json
{
  "ok": true,
  "session_id": "xp_01J...",
  "state": "collecting"
}
```

后续：

```bash
xprobe session show xp_01J... --json
xprobe session stop xp_01J... --json
xprobe session export xp_01J... --format chrome
```

## 9.3 Daemon

daemon 不是 Agent 组件，也不是模型服务。

仅在以下场景需要：

* 非 root CLI 通过受控服务使用 BPF。
* 多用户权限管理。
* 后台会话。
* 多个并发采集任务。
* 长时间运行。
* 对采集资源实施统一限制。

第一阶段可先实现单进程前台模式，再逐步提取 daemon。

---

# 10. Host 和 Device 采集边界

## 10.1 eBPF

Host 侧支持动态附着：

* uprobe。
* uretprobe。
* kprobe。
* kretprobe。
* tracepoint。
* 系统调用。
* 调度事件。
* 后续支持 USDT。

eBPF 适合捕获：

```text
用户态函数入口和返回
内核函数
线程切换
线程唤醒
系统调用
网络和文件系统事件
```

## 10.2 CUPTI

CUPTI Activity 和 Callback 采集需要目标进程内部存在 CUPTI 组件。

正式支持路径：

1. 启动时通过 `LD_PRELOAD` 加载。
2. 业务程序显式链接。
3. 通过业务已有插件机制加载。
4. 容器或服务启动配置中预加载。

必须明确：

```text
eBPF 可以从外部动态附着，
但 CUPTI 不天然等于可无条件外部附加到任意运行中 CUDA 进程。
```

第一版不把 `ptrace + dlopen` 注入作为正式能力。

运行中注入只能作为后续实验性模块，并且需要：

* 用户显式批准。
* 独立安全设计。
* 兼容性检测。
* 完整失败回滚。
* 不影响默认使用路径。

---

# 11. 事件模型

统一事件结构：

```rust
struct Event {
    schema_version: u16,

    session_id: String,
    event_id: String,
    sequence: u64,

    source: EventSource,
    event_type: EventType,

    pid: u32,
    tid: u32,
    cpu: Option<u32>,

    timestamp_raw: u64,
    timestamp_ns: u64,
    clock_domain: ClockDomain,
    timestamp_error_ns: Option<u64>,

    process_start_time: Option<u64>,

    host: Option<HostEvent>,
    cuda: Option<CudaEvent>,

    attributes: Map<String, Value>,
}
```

## 11.1 Host Event

```rust
struct HostEvent {
    probe_kind: HostProbeKind,

    binary_path: Option<String>,
    build_id: Option<String>,
    symbol: Option<String>,
    offset: Option<u64>,

    return_value: Option<i64>,
    arguments: Vec<ArgumentValue>,
}
```

默认不采集参数。

参数采集必须：

* 用户显式开启。
* 限制类型和长度。
* 明确 ABI。
* 禁止默认解引用任意指针。
* 记录读取失败。
* 支持全局策略禁止。

## 11.2 CUDA Event

```rust
struct CudaEvent {
    device_id: Option<u32>,
    context_id: Option<u32>,
    stream_id: Option<u64>,

    correlation_id: Option<u32>,
    runtime_correlation_id: Option<u32>,

    callback_domain: Option<u32>,
    callback_id: Option<u32>,

    kernel_name: Option<String>,
    kernel_name_mangled: Option<String>,

    start_ns: Option<u64>,
    end_ns: Option<u64>,

    grid: Option<Dim3>,
    block: Option<Dim3>,

    bytes: Option<u64>,
    memcpy_kind: Option<MemcpyKind>,
}
```

---

# 12. 事件选择器

采用稳定、可读、可序列化的事件选择器。

## 12.1 Host 函数

```text
uprobe:/srv/app/libserver.so:handle_request:entry
uprobe:/srv/app/libserver.so:handle_request:return
uprobe:/srv/app/libserver.so:+0x1234:entry
```

## 12.2 Kernel 和 Tracepoint

```text
kprobe:tcp_sendmsg:entry
kprobe:tcp_sendmsg:return
tracepoint:sched:sched_switch
tracepoint:sched:sched_wakeup
```

## 12.3 CUDA API

```text
cuda:runtime_api:cudaLaunchKernel:entry
cuda:runtime_api:cudaLaunchKernel:exit
cuda:driver_api:cuLaunchKernel:entry
cuda:driver_api:cuLaunchKernel:exit
```

## 12.4 GPU Activity

```text
cuda:kernel_start:name~flash.*
cuda:kernel_end:name~flash.*
cuda:memcpy_start:kind=HtoD
cuda:memcpy_end:kind=DtoH
cuda:memset_start
cuda:memset_end
```

---

# 13. CLI 设计

## 13.1 `doctor`

```bash
xprobe doctor --json
```

检查：

* Linux 内核版本。
* BTF。
* eBPF 能力。
* 当前权限。
* lockdown。
* `perf_event_paranoid`。
* `ptrace_scope`。
* NVIDIA Driver。
* CUDA。
* CUPTI。
* 容器环境。
* PID namespace。
* 当前功能矩阵。

输出：

```json
{
  "schema_version": "1.0",
  "ok": true,
  "capabilities": {
    "uprobe": true,
    "uretprobe": true,
    "tracepoint": true,
    "cuda_callback": true,
    "cuda_activity": true,
    "runtime_injection": false
  },
  "warnings": []
}
```

## 13.2 `inspect`

```bash
xprobe inspect --pid 1234 --json
```

输出：

* 可执行文件。
* 命令行。
* UID/GID。
* Host PID 和 namespace PID。
* cgroup。
* mount namespace。
* 已加载共享库。
* `libcuda`。
* `libcudart`。
* `xprobe-cupti`。
* CUDA context 是否已创建。
* 可用采集能力。

## 13.3 `discover`

```bash
xprobe discover processes --gpu --json
xprobe discover symbols --pid 1234 --regex 'handle_.*' --json
xprobe discover cuda-kernels --pid 1234 --duration 5s --json
xprobe discover tracepoints --regex 'sched_.*' --json
```

`discover` 只进行发现，不启动正式测量。

## 13.4 `resolve`

```bash
xprobe resolve \
  --pid 1234 \
  --event 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --json
```

返回解析后的：

```text
实际二进制路径
Build ID
映射地址
文件偏移
符号
探针类型
目标 PID
```

## 13.5 `validate`

```bash
xprobe validate \
  --pid 1234 \
  --from 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after \
  --json
```

检查：

* 事件语法。
* 符号是否存在。
* 目标进程是否匹配。
* CUPTI 是否已加载。
* 关联键是否合法。
* 是否缺少必要能力。
* 是否可能产生过高事件率。
* 是否存在明显歧义。
* 所需权限。
* 是否会修改目标进程。

示例：

```json
{
  "ok": true,
  "valid": true,
  "requirements": {
    "needs_ebpf": true,
    "needs_cupti": true,
    "target_restart_required": false,
    "target_mutation": false
  },
  "resolved": {
    "start": {
      "binary": "/srv/app/libserver.so",
      "symbol": "handle_request",
      "offset": 183040
    },
    "end": {
      "candidate_kernel_names": [
        "flash_fwd_kernel_sm90"
      ]
    }
  },
  "warnings": [
    {
      "code": "HEURISTIC_CORRELATION",
      "message": "The selected first-after policy does not prove request-level causality."
    }
  ]
}
```

## 13.6 `measure`

```bash
xprobe measure \
  --pid 1234 \
  --from 'uprobe:/srv/app/libserver.so:handle_request:entry' \
  --to 'cuda:kernel_start:name~flash.*' \
  --match first-after \
  --samples 100 \
  --timeout 30s \
  --json
```

必须要求：

* `--samples` 或 `--duration` 至少一个。
* 默认存在最大持续时间。
* 默认存在最大事件数量。
* 退出时自动清理。

## 13.7 `trace`

```bash
xprobe trace \
  --pid 1234 \
  --spec request-to-gpu.yaml \
  --output trace.json \
  --json
```

用于多事件、多阶段采集。

## 13.8 `session`

```bash
xprobe session list --json
xprobe session show <session-id> --json
xprobe session stop <session-id�戳
CUPTI 标准化时间戳
CUPTI 版本
设备 ID
context ID
stream ID
转换元信息
```

## 16.3 结果误差

结果必须报告：

```json
{
  "latency_ns": 183420,
  "estimated_timestamp_error_ns": 2500,
  "clock_alignment": "cupti_normalized_to_host_monotonic",
  "dropped_events": 0
}
```

亚微秒结果不得在没有误差说明的情况下被描述为精确结论。

---

# 17. 输出格式

## 17.1 人类可读摘要

```text
Measurement: launch_to_kernel
Target: PID 1234

Samples:
  matched             100
  unmatched starts      2
  unmatched ends        0
  dropped events        0

Latency:
  min      13.0 µs
  p50      28.0 µs
  p90      61.0 µs
  p95      84.0 µs
  p99     192.0 µs
  max     314.0 µs
  mean     35.6 µs

Correlation:
  method       CUPTI runtime correlation ID
  confidence   exact

Clock:
  alignment    CUPTI to host monotonic
  est. error   ≤ 2.5 µs
```

## 17.2 JSON

```json
{
  "schema_version": "1.0",
  "ok": true,
  "session_id": "xp_01J...",
  "status": "completed",
  "measurement": {
    "name": "launch_to_kernel",
    "samples": {
      "matched": 100,
      "unmatched_start": 2,
      "unmatched_end": 0,
      "dropped": 0
    },
    "latency_ns": {
      "min": 13000,
      "p50": 28000,
      "p90": 61000,
      "p95": 84000,
      "p99": 192000,
      "max": 314000,
      "mean": 35600
    }
  },
  "correlation": {
    "method": "cupti_runtime_correlation_id",
    "confidence": 1.0
  },
  "clock": {
    "alignment": "cupti_normalized_to_host_monotonic",
    "estimated_error_ns": 2500
  },
  "collection": {
    "host_events": 304,
    "cuda_events": 202,
    "dropped_events": 0
  },
  "warnings": []
}
```

## 17.3 Chrome Trace

映射：

```text
Host 函数       → complete event
CUDA API        → complete event
GPU kernel      → complete event
GPU memcpy      → complete event
关联关系        → flow event
Host thread     → thread lane
CUDA stream     → virtual thread lane
```

## 17.4 原始事件

支持 JSON Lines：

```bash
xprobe export <session> --format jsonl
```

每一行对应一个版本化 Event。

---

# 18. 错误模型

统一错误：

```json
{
  "schema_version": "1.0",
  "ok": false,
  "error": {
    "code": "SYMBOL_NOT_FOUND",
    "message": "The requested symbol was not found.",
    "recoverable": true,
    "details": {
      "binary": "/srv/app/libserver.so",
      "symbol": "handle_request"
    },
    "hints": [
      "Run xprobe discover symbols.",
      "Specify an explicit binary offset.",
      "Provide a matching debug symbol file."
    ]
  }
}
```

建议错误码：

```text
PERMISSION_DENIED
TARGET_NOT_FOUND
TARGET_EXITED
TARGET_REUSED
AMBIGUOUS_TARGET
SYMBOL_NOT_FOUND
BINARY_NOT_MAPPED
INVALID_EVENT_SELECTOR
INVALID_CORRELATION_POLICY
CUPTI_NOT_AVAILABLE
CUPTI_AGENT_NOT_LOADED
CUDA_CONTEXT_NOT_FOUND
UNSUPPORTED_CUDA_VERSION
EVENT_RATE_TOO_HIGH
SESSION_LIMIT_EXCEEDED
NO_MATCHED_SAMPLES
HIGH_UNMATCHED_RATE
EVENTS_DROPPED
CLOCK_ALIGNMENT_FAILED
TRACE_EXPORT_FAILED
CLEANUP_FAILED
```

错误码属于稳定公共 API。

---

# 19. 性能要求

在事件率低于每秒 10,000 条时，工程目标：

```text
目标进程额外 CPU 开销      < 2%
daemon/collector CPU       < 1 个核心
P50 延迟扰动               < 1%
额外内存占用               < 128 MB
事件丢失                   0
```

这些是需要 benchmark 验证的目标，不是无条件承诺。

## 19.1 高事件率保护

系统必须支持：

* 内核侧 PID/TID 过滤。
* 事件类型过滤。
* kernel 名称过滤尽量前移。
* 最大事件率。
* 最大事件数量。
* 最大内存占用。
* 采样。
* 超限告警。
* 丢弃而不阻塞目标进程。

## 19.2 eBPF 热路径

只允许：

```text
读取时间
读取 PID/TID/CPU
读取少量预定义参数
更新小型 map
写入 ring buffer
```

禁止：

* 正则匹配。
* 符号解析。
* 大型字符串处理。
* 大对象复制。
* 任意内存遍历。
* 复杂分析。

## 19.3 CUPTI Callback

禁止：

* 阻塞 IPC。
* 文件写入。
* 网络请求。
* 大量堆分配。
* 符号化。
* 复杂统计。

使用：

* 预分配 buffer。
* 无锁或低锁队列。
* 独立发送线程。
* 异步解析。
* 丢失计数。

---

# 20. 安全模型

## 20.1 默认只读

不得：

* 修改函数参数。
* 修改返回值。
* 修改 CUDA 调用。
* 修改业务内存。
* 修改 GPU buffer。
* 阻塞业务线程。
* 自动注入共享库。

## 20.2 默认不采集敏感数据

默认禁止采集：

* 字符串参数。
* 请求正文。
* 环境变量。
* 文件内容。
* 网络 payload。
* Token 和密码。
* 任意指针指向的内存。
* GPU tensor 内容。

## 20.3 权限

优先最小 capability：

```text
CAP_BPF
CAP_PERFMON
```

只有实验性注入功能才考虑：

```text
CAP_SYS_PTRACE
```

不得因为实现方便就要求长期完整 root 权限。

## 20.4 PID 重用

所有目标必须使用：

```text
PID + process start time
```

作为身份。

## 20.5 容器

必须解析：

* Host PID。
* Namespace PID。
* Mount namespace。
* cgroup。
* 容器 ID。
* 目标 namespace 中的二进制路径。
* Host 可见二进制路径。

---

# 21. 可靠性

必须保证：

* CLI 被中断后尽力清理 probe。
* 目标进程退出后自动停止。
* daemon 崩溃后内核 probe 自动 detach。
* CUPTI Agent 与采集器断连时不阻塞目标进程。
* 未识别 CUPTI record 可跳过并计数。
* 单条 record 解析失败不终止整个会话。
* 所有会话有最大时长和资源限制。
* 每个 attach 路径都有 det`text
marker
CUDA API entry
CUDA API exit
kernel start
kernel end
```

全部存在并可正确排序。

## 阶段 1：基础 CLI 和 Schema

实现：

* CLI 框架。
* Event Schema。
* Error Schema。
* `doctor`。
* `inspect`。
* `--json`。
* 统一退出码。
* 非交互模式。

## 阶段 2：Host 探针

实现：

* uprobe。
* uretprobe。
* tracepoint。
* BPF ring buffer。
* PID/TID 过滤。
* 函数 entry/return 配对。
* dropped-event 统计。

## 阶段 3：CUPTI Agent

实现：

* `LD_PRELOAD` 加载。
* Runtime Callback。
* Driver Callback。
* Kernel Activity。
* Memcpy Activity。
* Buffer pool。
* 与 collector 的本地 IPC。

## 阶段 4：统一时间线

实现：

* Event normalization。
* Host/CUPTI 时钟对齐。
* 原始与标准化时间戳。
* 有限窗口重排。
* JSONL 输出。

## 阶段 5：关联与测量

实现：

```text
exact
first_after
nearest
stack_nested
stream_order
```

输出：

* 样本。
* 未匹配事件。
* 歧义。
* 置信度。
* 延迟统计。
* 误差预算。

## 阶段 6：正式 CLI 工作流

实现：

```text
discover
resolve
validate
measure
trace
session
export
```

## 阶段 7：仓库内 Skills

实现：

```text
skills/xprobe-measure-latency
skills/xprobe-debug-gpu-gap
skills/xprobe-development
```

加入：

* 任务流程。
* 错误处理。
* 安全规则。
* 示例配置。
* 结果校验脚本。

## 阶段 8：Agent Contract Tests

分别测试：

* Claude Code。
* Codex CLI。
* Cursor。
* 其他可执行 shell 的 coding agent。

重点验证共同 CLI/Skill 设计，而不是开发平台专属插件。

## 阶段 9：后台会话和 daemon

在前台模式稳定后实现：

* 会话持久化。
* 非 root 客户端。
* 权限策略。
* 并发会话。
* 资源限制。
* stale session cleanup。

## 阶段 10：业务关联

实现：

```c
xprobe_correlation_push(uint64_t id);
xprobe_correlation_pop();
xprobe_mark(uint64_t id);
```

并支持：

* External correlation。
* USDT。
* 跨线程业务上下文。
* 可选 OpenTelemetry ID 映射。

## 阶段 11：实验性运行中注入

单独设计和评审，不阻塞正式版本。

---

# 24. 首轮 Coding Agent 任务清单

## Task 1：初始化仓库

建立：

```text
Rust workspace
CMake
eBPF build
CUPTI build
justfile
基础 CI
```

验收：

```bash
just build
just test
```

## Task 2：定义公共 Schema

完成：

* Event。
* HostEvent。
* CudaEvent。
* Error。
* Capability。
* MeasurementSpec。
* MeasurementResult。

生成 JSON Schema，并加入 round-trip 测试。

## Task 3：实现 `doctor`

检查：

* BPF。
* 权限。
* Driver。
* CUDA。
* CUPTI。
* 容器。
* namespace。

支持人类输出和 JSON 输出。

## Task 4：实现最小 uprobe

命令：

```bash
xprobe dev uprobe \
  --pid <pid> \
  --binary <path> \
  --symbol <symbol> \
  --json
```

输出：

```text
timestamp
pid
tid
cpu
probe ID
```

## Task 5：实现最小 CUPTI Agent

记录：

```text
cudaLaunchKernel entry
cudaLaunchKernel exit
kernel start
kernel end
correlation ID
```

## Task 6：统一事件收集

把 eBPF 和 CUPTI 事件写入相同 JSONL。

## Task 7：实现 `resolve`

支持：

* PIE。
* 共享库。
* `/proc/<pid>/maps`。
* Build ID。
* symbol。
* offset。

## Task 8：实现 `validate`

只做确定性检查，不附加正式采集 probe。

## Task 9：实现第一个 `measure`

支持：

```text
start selector
end selector
exact
first_after
sample limit
duration limit
```

## Task 10：实现统计和数据质量

输出：

```text
min
mean
p50
p90
p95
p99
max
dropped
unmatched
ambiguity
clock error
```

## Task 11：Chrome Trace

生成 Host thread 和 CUDA stream lane。

## Task 12：加入第一个 Skill

完成：

```text
skills/xprobe-measure-latency/SKILL.md
```

并以示例 CUDA 程序验证 Codex、Claude Code 和 Cursor 都可以按照 Skill 完成同一任务。

---

# 25. 首个正式版本验收标准

首个版本必须：

1. 支持 Linux x86_64。
2. 支持 NVIDIA CUDA。
3. 支持启动时加载 CUPTI Agent。
4. 支持动态附着 uprobe 和 uretprobe。
5. 支持 CUDA Runtime/Driver Callback。
6. 支持 kernel 和 memcpy Activity。
7. 关联 CUDA API 与 GPU Activity。
8. 测量 Host 到 Device 的延迟。
9. 输出 p50、p90、p95、p99。
10. 报告 dropped、unmatched 和 ambiguity。
11. 报告时钟和估计误差。
12. 导出 Chrome Trace。
13. 所有主要命令支持 JSON。
14. 所有命令支持非交互模式。
15. 所有错误使用稳定错误码。
16. 默认不采集业务参数和内存。
17. 默认不执行运行中进程注入。
18. 仓库包含可直接使用的 Skills。
19. Claude Code、Codex 和 Cursor 均能通过相同 CLI 完成标准测试。
20. 任意会话结束后不遗留 probe 和采集状态。

标准演示：

```text
在持续运行的 CUDA 推理服务中：

1. 服务启动时已加载 xprobe CUPTI Agent。
2. 对 handle_request 动态附加 uprobe。
3. 采集 100 次请求。
4. 测量：
   handle_request → cudaLaunchKernel
   cudaLaunchKernel → kernel start
   kernel start → kernel end
   kernel end → handle_request return
5. 输出 JSON 统计。
6. 导出 Chrome Trace。
7. 显示 dropped event。
8. 显示 unmatched event。
9. 显示关联方法和置信度。
10. 完整清理所有探针。
```

---

# 26. 最终成功定义

`xprobe` 成功的标准不是它是否内置了 Agent，而是外部 Agent 是否能像使用编译器、调试器和测试工具一样可靠地使用它。

理想交互：

```text
用户：
测一下 handle_request 到第一个 attention kernel 开始的延迟。

Coding Agent：
1. 阅读代码和 xprobe Skill。
2. 找到目标进程。
3. 执行 doctor 和 inspect。
4. 解析 handle_request。
5. 发现候选 kernel。
6. 生成测量配置。
7. 执行 validate。
8. 运行有界采集。
9. 检查数据质量。
10. 根据证据解释结果。
```

其中 `xprobe` 只负责确定性步骤：

```text
发现
解析
校验
采集
关联
统计
导出
清理
```

最终产品定义：

> `xprobe` 是一个面向人类和 coding agent 的确定性运行时测量工具。它通过稳定的 CLI、版本化 JSON Schema、结构化错误和仓库内 Skills，使 Claude Code、Codex、Cursor 及其他 Agent 能够安全、精确、可复现地测量 Host 与 GPU 事件之间的时间关系，而不要求 `xprobe` 自身接入任何语言模型或 Agent 框架。

