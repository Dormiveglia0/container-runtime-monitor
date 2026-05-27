# Container Runtime Monitor

基于 eBPF 的容器运行时安全检测系统，用于监测 Docker 容器内的命令执行与敏感文件访问行为，并通过规则引擎识别可疑操作、生成告警、持久化事件数据，提供本地 Web 控制台用于查看运行时安全态势。

## 功能概览

- 使用 eBPF tracepoint 采集容器内 `execve` 命令执行事件
- 使用 eBPF tracepoint 采集容器内 `openat` 文件访问事件
- 从 `/proc/<pid>/cgroup` 解析 Docker 容器 ID
- 通过 Docker Unix Socket 获取容器名称、镜像、状态等元数据
- 基于 YAML 配置加载命令执行与敏感文件访问检测规则
- 对交互式 shell、下载工具、netcat、命名空间/挂载工具、权限变更命令进行告警
- 对 Docker Socket、`/etc/shadow`、`/etc/passwd`、`/root/.ssh/`、敏感 `/proc`、`/sys` 写入等文件访问进行告警
- 使用 SQLite 持久化事件和告警
- 提供 Web Dashboard、事件列表、告警列表和 JSON API

## 系统架构

```text
Docker Container
      │
      ▼
Linux Kernel Tracepoints
  ├── sys_enter_execve
  └── sys_enter_openat
      │
      ▼
eBPF Programs + Ring Buffer
      │
      ▼
Agent
  ├── 事件解码
  ├── 容器识别
  ├── Docker 元数据解析
  ├── 规则匹配
  └── SQLite 写入
      │
      ▼
Web Console / JSON API
```

## 项目结构

```text
.
├── bpf/
│   ├── execve.bpf.c      # execve 事件采集程序
│   └── file.bpf.c        # openat 文件访问采集程序
├── cmd/
│   ├── agent/            # 运行时监测 Agent
│   └── web/              # Web 控制台
├── configs/
│   └── rules.yaml        # 检测规则配置
├── internal/
│   ├── collector/        # bpf2go 生成入口
│   ├── container/        # 容器识别与 Docker inspect
│   ├── rule/             # 规则加载与匹配
│   └── storage/          # SQLite 写入与查询
├── Makefile
├── go.mod
└── go.sum
```

## 环境要求

- Linux，内核支持 eBPF tracepoint 与 BTF
- Go 1.24+
- clang / llvm
- bpftool
- Docker
- root 权限，或具备加载 eBPF 程序和读取 Docker Socket 的权限

## 构建

```bash
make build
```

构建流程会自动完成：

1. 基于 `/sys/kernel/btf/vmlinux` 生成 `bpf/vmlinux.h`
2. 使用 bpf2go 生成 eBPF Go 绑定与 object 文件
3. 编译监测 Agent 到 `bin/agent`

本地生成文件包括：

- `bpf/vmlinux.h`
- `internal/collector/execve_bpfel.go`
- `internal/collector/execve_bpfel.o`
- `internal/collector/file_bpfel.go`
- `internal/collector/file_bpfel.o`

这些文件由构建流程生成，不提交到 Git 仓库。

## 运行 Agent

```bash
sudo make run
```

Agent 启动后会：

- 加载 `execve` 和 `openat` eBPF 程序
- 监听 Docker 容器内的命令执行和敏感文件访问行为
- 加载 `configs/rules.yaml` 检测规则
- 将事件与告警写入 `data/monitor.db`
- 在终端输出事件与告警摘要

## 运行 Web 控制台

另开一个终端执行：

```bash
make web
```

默认访问地址：

```text
http://127.0.0.1:8080
```

Web 控制台包含：

- Dashboard：事件、告警和容器数量统计
- Events：事件列表
- Alerts：告警列表

JSON API：

- `GET /api/stats`
- `GET /api/events`
- `GET /api/alerts`

## 规则配置

检测规则位于 `configs/rules.yaml`。

规则类型：

- `exec_rules`：按命令名匹配容器内命令执行行为
- `file_rules`：按路径、路径前缀、访问模式匹配敏感文件访问行为

文件访问规则支持：

- `access: any`
- `access: read`
- `access: write`
- `exact` 精确路径匹配
- `prefixes` 路径前缀匹配
- `proc_sensitive` 敏感 `/proc/<pid>/...` 路径识别

## 数据存储

默认数据库路径：

```text
data/monitor.db
```

主要数据表：

- `events`：记录 `execve` 和 `file_open` 事件
- `alerts`：记录规则命中的告警事件

`data/` 为本地运行数据目录，不提交到 Git 仓库。

## 常用命令

```bash
make generate   # 生成 vmlinux.h 和 bpf2go 产物
make build      # 构建 Agent
make run        # 构建并运行 Agent
make build-web  # 构建 Web 控制台
make web        # 构建并运行 Web 控制台
make clean      # 清理构建与生成产物
```

## 检测规则示例

命令执行类告警：

- `exec.shell`：容器内启动 `bash` 或 `sh`
- `exec.downloader`：容器内执行 `curl` 或 `wget`
- `exec.netcat`：容器内执行 `nc`、`ncat` 或 `netcat`
- `exec.escape-tool`：容器内执行 `mount`、`setns`、`unshare` 或 `nsenter`
- `exec.permission-change`：容器内执行 `chmod` 或 `chown`

文件访问类告警：

- `file.docker-sock`：访问 Docker Socket
- `file.shadow-write`：写方式打开 `/etc/shadow`
- `file.passwd-write`：写方式打开 `/etc/passwd`
- `file.ssh-write`：写方式访问 `/root/.ssh/`
- `file.proc-sensitive`：访问敏感 `/proc` 路径
- `file.sys-write`：写方式访问 `/sys`
