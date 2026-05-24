# Container Runtime Monitor

基于 eBPF 的容器运行时安全检测系统，用于采集 Docker 容器内的 `execve` 行为，并基于规则检测可疑命令执行事件。

## 功能特性

- 使用 eBPF tracepoint 采集 `sys_enter_execve` 事件
- 解析进程 PID、PPID、UID、GID、命令、参数和 cgroup 信息
- 关联 Docker 容器 ID，过滤非容器进程
- 对 shell、下载工具、netcat、命名空间/挂载工具、权限修改命令进行告警
- 将执行事件和告警事件持久化到 SQLite

## 项目结构

```text
.
├── bpf/                  # eBPF C 程序
├── cmd/agent/            # agent 启动入口
├── internal/collector/   # bpf2go 生成代码和加载逻辑
├── internal/container/   # 容器进程解析
├── internal/rule/        # 安全检测规则
├── internal/storage/     # SQLite 存储
└── Makefile
```

## 环境要求

- Linux 内核支持 eBPF tracepoint
- Go 1.24+
- clang / llvm
- bpftool
- Docker
- root 权限或具备加载 eBPF 程序的权限

## 构建与运行

```bash
make build
sudo ./bin/agent
```

也可以直接执行：

```bash
sudo make run
```

运行后系统会监听 Docker 容器中的命令执行行为，并在终端输出执行事件与命中的告警规则。

`make build` 会先执行 `make generate`，基于 `/sys/kernel/btf/vmlinux` 生成本机的 `bpf/vmlinux.h`，再通过 bpf2go 生成 `internal/collector/execve_bpfel.go` 和 `internal/collector/execve_bpfel.o`。这些文件属于本地生成物，不提交到仓库。

## 规则示例

当前内置规则包括：

- `exec.shell`：容器中启动 `bash` 或 `sh`
- `exec.downloader`：容器中执行 `curl` 或 `wget`
- `exec.netcat`：容器中执行 `nc`、`ncat` 或 `netcat`
- `exec.escape-tool`：容器中执行 `mount`、`setns`、`unshare` 或 `nsenter`
- `exec.permission-change`：容器中执行 `chmod` 或 `chown`

## 数据存储

事件默认写入 `data/monitor.db`。该文件属于本地运行数据，不会提交到 Git 仓库。
