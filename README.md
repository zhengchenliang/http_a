# http_a

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)
[![h2o](https://img.shields.io/badge/built%20on-h2o-green.svg)](https://github.com/h2o/h2o)

High-performance, header-only HTTP/1.1 & HTTP/2 server library for modern C++, built on [h2o](https://github.com/h2o/h2o) and [libuv](https://github.com/libuv/libuv).

## Benchmark

On my computer: i7-1355U (10C/12T), 32GB RAM, Arch Linux 6.17.9, GCC 15.2.1

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                              BENCHMARK SUMMARY                                                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┫
┃ Test                          ┃ Conns ┃   Req/sec    ┃  Lat avg   ┃  Lat max  ┃    Errors       ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━╋━━━━━━━━━━━━━━╋━━━━━━━━━━━━╋━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━┫
┃ sync  plaintext               ┃   100 ┃       256552 ┃     0.39ms ┃     7.2ms ┃               0 ┃
┃ async plaintext               ┃   100 ┃       202489 ┃     0.49ms ┃     4.6ms ┃               0 ┃
┃ sync  JSON                    ┃   100 ┃       250323 ┃     0.40ms ┃    13.6ms ┃               0 ┃
┃ async JSON                    ┃   100 ┃       196178 ┃     0.51ms ┃    13.5ms ┃               0 ┃
┃ sync  POST echo               ┃   100 ┃       231302 ┃     0.43ms ┃    11.3ms ┃               0 ┃
┃ async POST echo               ┃   100 ┃       188111 ┃     0.53ms ┃    11.2ms ┃               0 ┃
┃ async build JSON              ┃   100 ┃       181112 ┃     0.55ms ┃    10.3ms ┃               0 ┃
┃ async POST process            ┃   100 ┃       181589 ┃     0.55ms ┃    10.7ms ┃               0 ┃
┃ async multi-header            ┃   100 ┃       185227 ┃     0.54ms ┃     4.4ms ┃               0 ┃
┃ async 4KB                     ┃   100 ┃       166739 ┃     0.60ms ┃    10.8ms ┃               0 ┃
┃ async 4KB gzip                ┃   100 ┃       166262 ┃     0.60ms ┃    15.2ms ┃               0 ┃
┃ sync  4KB                     ┃   100 ┃       182345 ┃     0.55ms ┃    23.0ms ┃               0 ┃
┃ sync  4KB gzip                ┃   100 ┃        53844 ┃     1.88ms ┃    62.1ms ┃               0 ┃
┃ sync  plain t=4               ┃   200 ┃       230229 ┃     0.89ms ┃    55.7ms ┃               0 ┃
┃ sync  plain t=8               ┃   200 ┃       236511 ┃     0.89ms ┃    64.0ms ┃               0 ┃
┃ sync  plain t=16              ┃   200 ┃       235511 ┃     0.84ms ┃    56.3ms ┃               0 ┃
┃ async plain t=4               ┃   200 ┃       185329 ┃     1.14ms ┃    77.3ms ┃               0 ┃
┃ async plain t=8               ┃   200 ┃       184871 ┃     1.08ms ┃    30.2ms ┃               0 ┃
┃ async plain t=16              ┃   200 ┃       182591 ┃     1.07ms ┃    39.4ms ┃               0 ┃
┃ sync  c=1                     ┃     1 ┃        90985 ┃     0.01ms ┃     1.7ms ┃               0 ┃
┃ sync  c=10                    ┃    10 ┃       231882 ┃     0.03ms ┃     1.3ms ┃               0 ┃
┃ sync  c=50                    ┃    50 ┃       238788 ┃     0.20ms ┃     5.3ms ┃               0 ┃
┃ sync  c=100                   ┃   100 ┃       235789 ┃     0.42ms ┃    10.1ms ┃               0 ┃
┃ sync  c=200                   ┃   200 ┃       226346 ┃     0.95ms ┃    71.4ms ┃               0 ┃
┃ sync  c=500                   ┃   500 ┃       209038 ┃     2.95ms ┃   268.4ms ┃               0 ┃
┃ async c=1                     ┃     1 ┃        41664 ┃     0.02ms ┃     1.4ms ┃               0 ┃
┃ async c=10                    ┃    10 ┃       193993 ┃     0.04ms ┃     1.3ms ┃               0 ┃
┃ async c=50                    ┃    50 ┃       202646 ┃     0.24ms ┃     4.6ms ┃               0 ┃
┃ async c=100                   ┃   100 ┃       196516 ┃     0.51ms ┃     5.9ms ┃               0 ┃
┃ async c=200                   ┃   200 ┃       180491 ┃     1.12ms ┃    39.1ms ┃               0 ┃
┃ async c=500                   ┃   500 ┃       170816 ┃     3.02ms ┃   143.6ms ┃               0 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━┻━━━━━━━━━━━━━━┻━━━━━━━━━━━━┻━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━┛
```

Scaling flat. Bottleneck at single uv loop anyways.

## Features

- **High Performance** — Built on h2o, one of the fastest HTTP servers
- **Async I/O** — Non-blocking event-driven architecture via libuv
- **Thread Pool** — Built-in work-stealing thread pool for async handlers
- **HTTP/2** — Full HTTP/2 support with automatic protocol negotiation
- **Compression** — gzip, deflate, and brotli compression
- **SSL/TLS** — Full HTTPS support via OpenSSL
- **JSON** — Native JSON handling via [nlohmann/json](https://github.com/nlohmann/json)
- **Header-Only** — Easy integration, just include and use
- **Process Execution** — Secure subprocess execution with timeout and capture
- **Security** — wordexp-based argument parsing prevents shell injection

## Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| C++ Compiler | C++20 | GCC 10+, Clang 12+ |
| CMake | ≥ 3.16 | |
| h2o | ≥ 2.2 | Static library (libh2o.a) |
| libuv | ≥ 1.0 | |
| OpenSSL | ≥ 1.1 | |
| zlib | — | |
| Brotli | — | |
| nlohmann/json | ≥ 3.11 | Auto-fetched by CMake |

### Install Dependencies

**Arch Linux:**
```bash
pacman -S openssl libuv zlib brotli
```

**Ubuntu/Debian:**
```bash
apt install libssl-dev libuv1-dev zlib1g-dev libbrotli-dev
```

**macOS:**
```bash
brew install openssl libuv zlib brotli
```

## Build

```bash
git clone https://github.com/user/http_a.git
cd http_a
mkdir build && cd build
cmake -DH2O_ROOT=/path/to/h2o ..
cmake --build . -j$(nproc)
```

### CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `H2O_ROOT` | — | Path to h2o installation |
| `HTTP_A_BUILD_EXAMPLES` | ON | Build example applications |
| `HTTP_A_BUILD_TESTS` | ON | Build test applications |

## Quick Start

### Hello World

```cpp
#include <http_a_server.hh>

int main()
{
  http_a app;

  app.get_("/", [](const http_q& _q, http_s& _s)
  {
    _s.status_(200);
    _s.send_text_("Hello, World!");
  });

  app.listen_("0.0.0.0", 8080);
  app.signal_();
  app.serve_();

  return 0;
}
```

### JSON API

```cpp
app.post_("/api/data", [](const http_q& _q, http_s& _s)
{
  auto body = nlohmann::json::parse(_q.body);
  
  _s.status_(200);
  _s.send_json_({
    {"received", body},
    {"status", "ok"}
  });
}, true); // async handler
```

### HTTPS Server

```cpp
http_a app;

app.ssl_("/path/to/cert.pem", "/path/to/key.pem");
app.listen_("0.0.0.0", 443);
app.signal_();
app.serve_();
```

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `http_a` | Main server class |
| `http_q` | Request object (read-only) |
| `http_s` | Response object (write) |
| `pth_t` | Thread pool |
| `exe_t` | Process executor |
| `exe_r` | Process execution result |

### Server (`http_a`)

```cpp
http_a app;

// SSL/TLS (call before listen)
app.ssl_("/path/to/cert.pem", "/path/to/key.pem");

// Bind to address(es)
app.listen_("0.0.0.0", 8080);
app.listen_("0.0.0.0", 8443);  // multiple ports

// Signal handling (graceful shutdown on SIGINT)
app.signal_();

// Start server
app.serve_();   // blocking (main thread)
app.start_();   // background thread
app.stop_();    // stop server

// Server info
int64_t ms = app.uptime_();  // uptime in milliseconds
```

### Route Registration

```cpp
// Handler signature
using http_f = std::function<void(const http_q&, http_s&)>;

// Method shortcuts
app.get_("/path", handler);
app.post_("/path", handler);
app.put_("/path", handler);
app.delete_("/path", handler);
app.patch_("/path", handler);
app.options_("/path", handler);
app.head_("/path", handler);

// Full signature with all options
app.register_("/path", "POST", handler,
  true,    // async (default: true)
  30000,   // timeout_ms (0 = no timeout)
  true,    // compress (default: true)
  100,     // compress_min_size
  1,       // gzip_quality (1-9)
  1        // brotli_quality (1-11)
);
```

### Request (`http_q`)

```cpp
[](const http_q& _q, http_s& _s)
{
  // URL components
  std::string url = _q.url_();              // "/api/v1/users?id=123"
  std::string path = _q.url_normal_();      // "/api/v1/users"
  std::string prefix = _q.url_prefix_();    // "/api/v1" (registered)
  std::string rest = _q.url_rest_();        // "/users"
  std::string query = _q.url_query_();      // "?id=123"

  // Query parameters
  std::string id = _q.query_("id");         // "123"
  bool has_id = _q.query_has_("id");        // true
  auto queries = _q.queries_();             // map<string, string>

  // Headers (keys are lowercase)
  std::string auth = _q.header_("authorization");
  bool has_ct = _q.header_has_("content-type");
  auto headers = _q.headers_();             // map<string, string>

  // Body
  std::string_view body = _q.body;          // raw body view
  size_t size = _q.size;                    // body size
  dat_t data = _q.data;                     // dat_t wrapper

  // Metadata
  std::string version = _q.http_vers_();    // "HTTP/1.1"
  std::string host = _q.http_auth_();       // host header
  tim_t time = _q.http_time_0_();           // request begin time
};
```

### Response (`http_s`)

```cpp
[](const http_q& _q, http_s& _s)
{
  // Status
  _s.status_(200);
  _s.status_(404, "Not Found");

  // Headers
  _s.header_("X-Custom", "value");
  _s.header_json_();   // Content-Type: application/json
  _s.header_text_();   // Content-Type: text/plain
  _s.header_html_();   // Content-Type: text/html

  // Body + send (convenience)
  _s.send_text_("Hello, World!");
  _s.send_json_({{"key", "value"}});
  _s.send_html_("<h1>Title</h1>");

  // Manual body + send
  _s.body_("content");
  _s.send_();

  // File serving
  _s.dat_get_("/path/to/file.txt");
  _s.send_(http_b::O);  // O = already on h2o pool

  // Connection control
  _s.stay_();   // force keep-alive
  _s.quit_();   // force close after response
};
```

### Process Execution

Execute external commands securely from request handlers:

```cpp
// Synchronous with full capture
exe_r result = _q.exe_load_(
  "ls",                  // command
  "-la /tmp",            // arguments (string or vector)
  "/home/user",          // working directory
  {{"PATH", "/usr/bin"}} // environment
);

if (result.exit_code == 0)
{
  _s.send_text_(result.stdout_info);
}

// Fire-and-forget (returns immediately)
_q.exe_fire_("backup.sh", "--full", "/var/data");

// With timeout and sampling
exe_r result = _q.exe_run_(
  "long_process",
  "--arg",
  "/tmp",
  {},        // env
  30000,     // timeout_ms
  3,         // capture: 0=none, 1=stdout, 2=stderr, 3=both, 4+=merge
  1000       // sample_period_ms (for monitoring)
);
```

**Execution Result (`exe_r`):**

| Field | Type | Description |
|-------|------|-------------|
| `pid` | `pid_t` | Process ID |
| `status` | `uint8_t` | 0=created, 1=spawned, 2=monitoring, 3=completed, 4=detached, 5+=failed |
| `exit_code` | `int` | Exit code (if normal exit) |
| `exit_sign` | `int` | Signal number (if signaled) |
| `timed_out` | `bool` | True if killed by timeout |
| `stdout_info` | `string` | Captured stdout |
| `stderr_info` | `string` | Captured stderr |

## Examples

### Static File Server

```cpp
app.get_("/static", [](const http_q& _q, http_s& _s)
{
  std::string path = "/var/www" + _q.url_rest_();
  
  // Security: prevent traversal
  if (path.find("..") != std::string::npos)
  {
    _s.status_(403);
    _s.send_text_("Forbidden");
    return;
  }

  if (_s.dat_get_(path) == 0)
  {
    _s.status_(200);
    _s.send_(http_b::O);
  }
  else
  {
    _s.status_(404);
    _s.send_text_("Not Found");
  }
}, true);
```

### REST API with CRUD

```cpp
std::unordered_map<std::string, nlohmann::json> store;
std::mutex store_mtx;

// GET /api/items/{id}
app.get_("/api/items", [&](const http_q& _q, http_s& _s)
{
  std::string id = /* extract from _q.url_rest_() */;
  std::lock_guard lock(store_mtx);
  
  auto it = store.find(id);
  if (it != store.end())
  {
    _s.send_json_(it->second);
  }
  else
  {
    _s.status_(404);
    _s.send_json_({{"error", "Not found"}});
  }
}, true);

// POST /api/items
app.post_("/api/items", [&](const http_q& _q, http_s& _s)
{
  auto item = nlohmann::json::parse(_q.body);
  std::string id = std::to_string(++next_id);
  
  std::lock_guard lock(store_mtx);
  store[id] = item;
  
  _s.status_(201);
  _s.send_json_({{"id", id}});
}, true);
```

### Health Check Endpoint

```cpp
app.get_("/health", [&](const http_q& _q, http_s& _s)
{
  _s.send_json_({
    {"status", "healthy"},
    {"uptime_ms", app.uptime_()},
    {"version", "1.0.0"}
  });
}, false);  // sync for low latency
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           http_a                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │   Routes    │  │  Thread Pool │  │   Process Executor     │  │
│  │  (http_h)   │  │   (pth_t)    │  │       (exe_t)          │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                            h2o                                  │
│              HTTP/1.1 · HTTP/2 · Compression · SSL              │
├─────────────────────────────────────────────────────────────────┤
│                           libuv                                 │
│                    Event Loop · Async I/O                       │
└─────────────────────────────────────────────────────────────────┘
```

**Request Flow:**

1. Connection arrives → libuv accepts → h2o creates socket
2. h2o parses HTTP → routes to registered handler
3. **Sync handler**: executes in event loop thread
4. **Async handler**: dispatched to thread pool → response via `uv_async`
5. h2o sends response → optional compression → connection managed

## Security Considerations

### Input Validation

- All query parameters are URL-decoded with null-byte rejection
- Command arguments use `wordexp()` for secure parsing
- No shell metacharacter injection possible
- Path traversal detection (`..`, `//`) recommended in file handlers

### Resource Limits

- Configurable request timeouts prevent hung connections
- Process execution timeouts prevent runaway subprocesses
- Thread pool sizing prevents resource exhaustion
- h2o memory pooling prevents excessive allocations

### Production Hardening

```cpp
// Enable compression for bandwidth savings
app.post_("/api", handler, true, 30000, true, 1024, 6, 4);

// Set reasonable timeouts
app.post_("/api/slow", handler, true, 60000);  // 60s timeout

// Graceful shutdown
app.signal_();
```

## Thread Safety

| Component | Thread Safety |
|-----------|---------------|
| `http_a` registration | NOT thread-safe (setup phase only) |
| `http_a` serve/start/stop | Thread-safe |
| `http_q` | Thread-safe (immutable) |
| `http_s` | NOT thread-safe (one response per request) |
| `pth_t` | Thread-safe |
| `exe_t` | Thread-safe |

## Performance Tips

1. **Use async handlers** for I/O-bound operations
2. **Use sync handlers** for CPU-light, latency-sensitive endpoints
3. **Enable compression** for text responses > 1KB
4. **Reuse connections** (HTTP/1.1 keep-alive, HTTP/2 multiplexing)
5. **Tune thread pool size**: `2 * CPU cores` is default

## License

MIT License — see [LICENSE](LICENSE)

## See Also

- [h2o](https://github.com/h2o/h2o) — The optimized HTTP server
- [libuv](https://github.com/libuv/libuv) — Cross-platform async I/O
- [nlohmann/json](https://github.com/nlohmann/json) — JSON for Modern C++
