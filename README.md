# SecureRun: Sandboxed Code Execution and Auto-Grading Engine

Operating Systems project, Section G, Sukkur IBA University. Instructor: Sir Abbas Mehdi.

| Member | Registration No. |
|---|---|
| Anisa (Group Leader) | 023-24-0222 |
| Mahnoor | 023-24-0207 |
| Inamullah | 023-24-0236 |

## What it does

SecureRun is a C program for Ubuntu Linux that compiles and runs untrusted C submissions the way an online judge does. Each submission runs inside a sandbox so that infinite loops, memory hogs, fork bombs and file snooping cannot harm the host. SecureRun then gives a verdict: Accepted, Wrong Answer, Time Limit Exceeded, Memory Limit Exceeded, Resource Limit Exceeded, Output Limit Exceeded, Runtime Error, Compile Error or System Error.

## How it works

1. Compile the submission with `gcc -static` as the unprivileged user `nobody` (`fork` + `execvp`).
2. Create a cgroup v2 with `memory.max` and `pids.max`.
3. Start the program with `clone()` in new PID, mount, network, IPC and UTS namespaces.
4. In the child: join the cgroup, `chroot` into a jail holding only the binary, redirect stdin/stdout, set `setrlimit` limits, drop privileges to uid 65534, then `execve`.
5. In the parent: read the output pipe, call `wait4(WNOHANG)`, and enforce a wall-clock timer.
6. Read `memory.events` and `pids.events`, decode the exit status, and compare the output with the expected output.
7. A semaphore-limited pool of threads judges several submissions at once.

| Threat | Mechanism | Verdict |
|---|---|---|
| Infinite loop | `RLIMIT_CPU` plus wall-clock timer | Time Limit Exceeded |
| Memory hog | cgroup `memory.max` | Memory Limit Exceeded |
| Fork bomb | cgroup `pids.max` | Resource Limit Exceeded |
| Endless output | 1 MB output cap | Output Limit Exceeded |
| File access | `chroot` and mount namespace | Blocked |
| Privilege escape | `setuid(65534)`, `NO_NEW_PRIVS` | No root rights |

## Requirements

- Ubuntu 22.04 or newer, or WSL2 with cgroups v2 (`stat -fc %T /sys/fs/cgroup` must print `cgroup2fs`)
- Root access (`sudo`)
- `sudo apt install build-essential`

## Build and run

```bash
make
sudo tests/run_tests.sh                      # safe tests
sudo WITH_FORKBOMB=1 tests/run_tests.sh      # adds the fork bomb (cgroups v2 required)
```

Judge your own program:

```bash
sudo ./securerun [-t cpu_s] [-m mem_MB] [-p max_pids] [-j workers] [-c] sub.c input.txt expected.txt [more triples...]
```

`-c` disables cgroups (fallback mode; not safe against fork bombs).

## Example result (WSL2, cgroups v2)

```
ID  SUBMISSION    VERDICT                    CPU(ms)   MEM(KB)
1   ac.c          Accepted                       4.1       256
2   wa.c          Wrong Answer                   4.5       512
3   tle.c         Time Limit Exceeded         3002.4       256
4   sleeper.c     Time Limit Exceeded            4.7       256
5   mle.c         Memory Limit Exceeded        336.2     65536
6   ole.c         Output Limit Exceeded          8.1       256
7   re.c          Runtime Error                  9.4       256
8   ce.c          Compile Error                  0.0         0
9   fs.c          Accepted                       4.6       256
10  forkbomb.c    Resource Limit Exceeded      505.7     18280
```

The full outputs and screenshots are in `docs/` and `screenshots/`. Valgrind reported 0 errors and no leaks for the judge process.

## File map

| Path | Purpose |
|---|---|
| `src/main.c` | Options, semaphore worker pool, results table |
| `src/compiler.c` | Compiles the submission with gcc |
| `src/cgroup.c`, `src/cgroup.h` | cgroups v2 create, limits, counters, cleanup |
| `src/runner.c` | Sandbox, execution, monitoring, verdict |
| `src/judge.c` | One job from start to finish, output comparison |
| `src/util.c`, `src/util.h` | File helpers, timing, verdict names |
| `src/common.h` | Shared types and configuration |
| `tests/` | Nine test programs, input and expected files, `run_tests.sh` |
| `docs/` | Report, slides, proposal, test outputs, Valgrind log |
| `screenshots/` | Terminal evidence |

## Limitations

- Single-file C programs only, with input on stdin and output on stdout.
- Memory and fork-bomb verdicts need cgroups v2 and root.
- The sandbox relies on the kernel; a `seccomp` filter would be a future improvement.
