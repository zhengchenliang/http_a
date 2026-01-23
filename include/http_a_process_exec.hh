#pragma once

struct exe_c;
struct exe_r;
struct exe_p;

#include <cstdlib>
#include <cstddef>
#include <unistd.h>
#include <wordexp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
#include <poll.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <chrono>

extern char **environ;

/* --------------------------------------------- */

struct exe_c // config
{
  std::string cmd;
  std::vector<std::string> args;
  std::string dir;
  std::unordered_map<std::string, std::string> env;
  uint64_t timeout_ms = 0; // 0 = no timeout; 1+ = timeout ms
  uint8_t capture = 0; // 0 = none; 1 = stdout; 2 = stderr; 3 = both; 4+ = merge stderr into stdout
  uint64_t period_ms = 0; // 0 = no sampling; 1+ = sampling period ms
  exe_c() = default;
  explicit exe_c(const std::string& _cmd) : cmd(_cmd) {}
  exe_c(const std::string& _cmd, const std::vector<std::string>& _args) : cmd(_cmd), args(_args) {}
  exe_c(const std::string& _cmd
    , const std::vector<std::string>& _args
    , const std::string& _dir
  ) : cmd(_cmd), args(_args), dir(_dir) {}
  exe_c(const std::string& _cmd
    , const std::vector<std::string>& _args
    , const std::string& _dir
    , const std::unordered_map<std::string, std::string>& _env
    , uint64_t _timeout_ms = 0, uint8_t _capture = 0, uint64_t _period_ms = 0
  ) : cmd(_cmd), args(_args), dir(_dir), env(_env)
    , timeout_ms(_timeout_ms), capture(_capture), period_ms(_period_ms) {}
  static inline void split_(const std::string &_str, std::vector<std::string> &_args)
  {
    _args.clear();
    if (_str.empty()) return;
    wordexp_t p;
    int ret = wordexp(_str.c_str(), &p, WRDE_NOCMD | WRDE_UNDEF); // prevent $(cmd) substitution and fail on undefined variable expansion
    if (ret != 0)
    {
      fprintf(stderr, "exe_c.split_() [%d]: wordexp failed %s\n", getpid(), _str.c_str());
      return; // wordexp failed
    }
    _args.reserve(p.we_wordc);
    for (size_t i = 0; i < p.we_wordc; i++)
    {
      _args.emplace_back(p.we_wordv[i]);
    }
    wordfree(&p);
  }
  static inline std::vector<std::string> split_(const std::string &_str)
  {
    std::vector<std::string> args;
    split_(_str, args);
    return args;
  }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  exe_c(const std::string& _cmd, const T& _args) : cmd(_cmd), args(split_(_args)) {}
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  exe_c(const std::string& _cmd
    , const T& _args
    , const std::string& _dir
  ) : cmd(_cmd), args(split_(_args)), dir(_dir) {}
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  exe_c(const std::string& _cmd
    , const T& _args
    , const std::string& _dir
    , const std::unordered_map<std::string, std::string>& _env
    , uint64_t _timeout_ms = 0, uint8_t _capture = 0, uint64_t _period_ms = 0
  ) : cmd(_cmd), args(split_(_args)), dir(_dir), env(_env)
    , timeout_ms(_timeout_ms), capture(_capture), period_ms(_period_ms) {}
  inline bool pipe_stdout_() const noexcept { return capture == 1 || capture > 2; }
  inline bool pipe_stderr_() const noexcept { return capture == 2 || capture == 3; }
};

struct exe_r // result
{
  uint64_t id;
  pid_t pid = -1;
  pid_t ppid = -1;
  uint8_t status = 7; // 0 = created; 1 = spawned; 2 = monitoring; 3 = completed; 4 = detached; 5+ = failed
  bool exit_normal = false; // true = normal; false = signaled
  int exit_code = -1;
  int exit_sign = 0;
  bool timed_out = false;
  bool core_dumped = false;
  std::chrono::steady_clock::time_point init_time;
  std::chrono::steady_clock::time_point fina_time;
  uint64_t stdout_size = 0;
  uint64_t stderr_size = 0;
  std::string stdout_info = "";
  std::string stderr_info = "";
  std::vector<exe_p> samples;
};

struct exe_p // sample
{
  uint64_t elapsed_us; // us since process start
  char state; // R (running), S (sleeping), D (disk sleep), T (stopped), Z (zombie), etc.
  int num_threads;
};

class exe_t // executor
{
public:
  const uint64_t page_size = static_cast<uint64_t>(sysconf(_SC_PAGESIZE) < 0 ? 4096 : sysconf(_SC_PAGESIZE));
  std::atomic<uint64_t> this_id = {0};
  static inline short exe_p_(pid_t _pid, exe_p& _sample) // 1338699 (cat) R 1338003 1338699 1338003 34826 1338699 4194304 92 0 0 0 0 0 0 0 20 0 1 0 2595845 15089664 856 18446744073709551615 103164234764288 103164234779441 140725970130992 0 0 0 0 0 0 0 0 0 17 5 0 0 0 0 0 103164234791600 103164234793064 103164958187520 140725970131881 140725970131901 140725970131901 140725970145259 0
  {
    std::ostringstream path;
    path << "/proc/" << _pid << "/stat";
    std::ifstream file(path.str());
    if (!file.is_open()) return -1;
    std::string line;
    if (!std::getline(file, line)) return -2;
    size_t start = line.find('(');
    size_t end = line.rfind(')');
    if (start == std::string::npos || end == std::string::npos || end <= start) return -3;
    size_t state_pos = end + 2;
    if (state_pos >= line.length()) return -4;
    std::istringstream iss(line.substr(state_pos));
    char state;
    long ppid, pgrp, session, tty_nr, tpgid;
    unsigned long flags, minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, num_threads;
    if (!(iss >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid
      >> flags >> minflt >> cminflt >> majflt >> cmajflt
      >> utime >> stime >> cutime >> cstime >> priority >> nice >> num_threads)
    ) return -5;
    _sample.state = state;
    _sample.num_threads = static_cast<int>(num_threads);
    return 0;
  }
  exe_t() { init_(); }
  ~exe_t() { fina_(); }
  exe_t(const exe_t&) = delete;
  exe_t& operator=(const exe_t&) = delete;
  exe_t(exe_t&&) = delete;
  exe_t& operator=(exe_t&&) = delete;
  inline void init_() { this_id.store(1); }
  inline void fina_() { this_id.store(0); }
  inline short execute_(const exe_c& _config, exe_r& _result)
  {
    // 1. setup pipes
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    _result.id = this_id.fetch_add(1);
    _result.status = 0; // created
    if (_config.pipe_stdout_())
    {
      if (pipe(stdout_pipe) == -1)
      {
        perror("exe_t.execute_(): ---pipe stdout---");
        _result.status = 5;
        return -1;
      }
    }
    if (_config.pipe_stderr_())
    {
      if (pipe(stderr_pipe) == -1)
      {
        perror("exe_t.execute_(): ---pipe stderr---");
        if (_config.pipe_stdout_())
        {
          close(stdout_pipe[0]);
          close(stdout_pipe[1]);
        }
        _result.status = 5;
        return -2;
      }
    }
    // 2. build argv
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(_config.cmd.c_str()));
    for (const auto& arg : _config.args)
    {
      argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(NULL);
    // 3. build envp
    std::vector<std::string> env_storage;
    std::vector<char*> envp;
    if (!_config.env.empty())
    {
      for (const auto& kv : _config.env)
      {
        env_storage.push_back(kv.first + "=" + kv.second);
      }
      for (auto& e : env_storage)
      {
        envp.push_back(const_cast<char*>(e.c_str()));
      }
      envp.push_back(NULL);
    }
    // 4. setup posix_spawn attributes and file actions
    posix_spawnattr_t attr;
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_init(&file_actions);
    // 5. set flags for fire-and-forget (detached) mode
    if (_config.period_ms == 0 && _config.capture == 0)
    {
      posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
      posix_spawnattr_setpgroup(&attr, 0); // new process group
    }
    // 6. setup file redirections
    if (_config.pipe_stdout_())
    {
      posix_spawn_file_actions_adddup2(&file_actions, stdout_pipe[1], STDOUT_FILENO);
      posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[0]);
      posix_spawn_file_actions_addclose(&file_actions, stdout_pipe[1]);
    }
    if (_config.capture > 1)
    {
      if (_config.capture > 3) posix_spawn_file_actions_adddup2(&file_actions, STDOUT_FILENO, STDERR_FILENO);
      else
      {
        posix_spawn_file_actions_adddup2(&file_actions, stderr_pipe[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[0]);
        posix_spawn_file_actions_addclose(&file_actions, stderr_pipe[1]);
      }
    }
    // 7. change directory if specified
    if (!_config.dir.empty()) posix_spawn_file_actions_addchdir_np(&file_actions, _config.dir.c_str());
    _result.init_time = std::chrono::steady_clock::now();
    // 8. spawn process
    pid_t pid;
    int spawn_ret;
    if (!_config.env.empty()) spawn_ret = posix_spawnp(&pid, _config.cmd.c_str(), &file_actions, &attr, argv.data(), envp.data());
    else spawn_ret = posix_spawnp(&pid, _config.cmd.c_str(), &file_actions, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&file_actions);
    posix_spawnattr_destroy(&attr);
    if (spawn_ret != 0)
    {
      errno = spawn_ret;
      perror("exe_t.execute_(): ---posix_spawnp---");
      if (_config.capture > 0)
      {
        if (stdout_pipe[0] != -1) { close(stdout_pipe[0]); stdout_pipe[0] = -1; }
        if (stdout_pipe[1] != -1) { close(stdout_pipe[1]); stdout_pipe[1] = -1; }
        if (stderr_pipe[0] != -1) { close(stderr_pipe[0]); stderr_pipe[0] = -1; }
        if (stderr_pipe[1] != -1) { close(stderr_pipe[1]); stderr_pipe[1] = -1; }
      }
      _result.status = 6;
      return -3;
    }
    _result.pid = pid;
    _result.ppid = getpid();
    _result.status = 1; // spawned
    // 9A. periodic sampling
    if (_config.period_ms > 0)
    {
      if (_config.pipe_stdout_())
      {
        close(stdout_pipe[1]); // close write end: parent never write
        stdout_pipe[1] = -1;
        fcntl(stdout_pipe[0], F_SETFL, fcntl(stdout_pipe[0], F_GETFL, 0) | O_NONBLOCK); // read end set non-block
      }
      if (_config.pipe_stderr_())
      {
        close(stderr_pipe[1]); // close write end: parent never write
        stderr_pipe[1] = -1;
        fcntl(stderr_pipe[0], F_SETFL, fcntl(stderr_pipe[0], F_GETFL, 0) | O_NONBLOCK); // read end set non-block
      }
      _result.status = 2; // monitoring
      sample_(_config, _result, stdout_pipe, stderr_pipe);
      if (stdout_pipe[0] != -1) { close(stdout_pipe[0]); stdout_pipe[0] = -1; }
      if (stderr_pipe[0] != -1) { close(stderr_pipe[0]); stderr_pipe[0] = -1; }
    }
    // 9B. one-off capture
    else if (_config.capture > 0)
    {
      if (_config.pipe_stdout_())
      {
        close(stdout_pipe[1]); // close write end: parent never write
        stdout_pipe[1] = -1;
        fcntl(stdout_pipe[0], F_SETFL, fcntl(stdout_pipe[0], F_GETFL, 0) | O_NONBLOCK); // read end set non-block
      }
      if (_config.pipe_stderr_())
      {
        close(stderr_pipe[1]); // close write end: parent never write
        stderr_pipe[1] = -1;
        fcntl(stderr_pipe[0], F_SETFL, fcntl(stderr_pipe[0], F_GETFL, 0) | O_NONBLOCK); // read end set non-block
      }
      _result.status = 2; // monitoring
      struct pollfd fds[2];
      int nfds = 0;
      if (_config.pipe_stdout_())
      {
        fds[nfds].fd = stdout_pipe[0];
        fds[nfds].events = POLLIN;
        nfds++;
      }
      if (_config.pipe_stderr_())
      {
        fds[nfds].fd = stderr_pipe[0];
        fds[nfds].events = POLLIN;
        nfds++;
      }
      char buf[page_size];
      bool stdout_open = _config.pipe_stdout_();
      bool stderr_open = _config.pipe_stderr_();
      while (stdout_open || stderr_open) // read from pipes until child exits AND all pipes are closed
      {
        int ready = poll(fds, nfds, -1); // -1 = block indefinitely: event-driven no CPU waste
        if (ready < 0)
        {
          if (errno == EINTR) continue; // interrupted by signal
          perror("exe_t.execute_(): ---poll---");
          break;
        }
        if (ready > 0)
        {
          for (int i = 0; i < nfds; i++)
          {
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
            {
              while (true)
              {
                ssize_t r = read(fds[i].fd, buf, page_size);
                if (r > 0)
                {
                  if (fds[i].fd == stdout_pipe[0])
                  {
                    _result.stdout_info.append(buf, r);
                    _result.stdout_size += r;
                  }
                  else
                  {
                    _result.stderr_info.append(buf, r);
                    _result.stderr_size += r;
                  }
                }
                else if (r == 0) // EOS: all data read then close pipe
                {
                  if (fds[i].fd == stdout_pipe[0]) stdout_open = false;
                  else stderr_open = false;
                  break;
                }
                else if (errno == EAGAIN || errno == EWOULDBLOCK)
                { // EAGAIN or EWOULDBLOCK: pipe is not ready to read
                  if (fds[i].revents & (POLLHUP | POLLERR))
                  {
                    if (fds[i].fd == stdout_pipe[0]) stdout_open = false;
                    else stderr_open = false;
                  }
                  break;
                }
                else // pipe read error: treat as closed
                {
                  perror("exe_t.execute_(): ---read---");
                  if (fds[i].fd == stdout_pipe[0]) stdout_open = false;
                  else stderr_open = false;
                  break;
                }
              }
            }
          }
          nfds = 0; // rebuild fds array with only open pipes
          if (stdout_open)
          {
            fds[nfds].fd = stdout_pipe[0];
            fds[nfds].events = POLLIN;
            nfds++;
          }
          if (stderr_open)
          {
            fds[nfds].fd = stderr_pipe[0];
            fds[nfds].events = POLLIN;
            nfds++;
          }
        }
      }
      int status;
      if (waitpid(pid, &status, 0) == -1)
      {
        perror("exe_t.execute_(): ---waitpid---");
        if (stdout_pipe[0] != -1) { close(stdout_pipe[0]); stdout_pipe[0] = -1; }
        if (stderr_pipe[0] != -1) { close(stderr_pipe[0]); stderr_pipe[0] = -1; }
        _result.status = 7; // failed
        return -4;
      }
      if (stdout_pipe[0] != -1) { close(stdout_pipe[0]); stdout_pipe[0] = -1; }
      if (stderr_pipe[0] != -1) { close(stderr_pipe[0]); stderr_pipe[0] = -1; }
      _result.fina_time = std::chrono::steady_clock::now();
      _result.status = 3; // completed
      if (WIFEXITED(status))
      {
        _result.exit_normal = true;
        _result.exit_code = WEXITSTATUS(status);
      }
      else if (WIFSIGNALED(status))
      {
        _result.exit_normal = false;
        _result.exit_sign = WTERMSIG(status);
      }
      _result.core_dumped = WCOREDUMP(status);
    }
    // 9C. fire-and-forget
    else _result.status = 4; // detached
    return 0;
  }
  inline exe_r execute_(const exe_c& _config)
  {
    exe_r result;
    execute_(_config, result);
    return result;
  }
  inline exe_r execute_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  )
  {
    exe_c config(_cmd, _args, _dir, _env, _timeout_ms, _capture, _period_ms);
    exe_r result;
    execute_(config, result);
    return result;
  }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r execute_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  ) { return execute_(_cmd, exe_c::split_(_args), _dir, _env, _timeout_ms, _capture, _period_ms); }
  inline exe_r monitor_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  )
  {
    exe_c config(_cmd, _args, _dir, _env, 0, 3, 0);
    exe_r result;
    execute_(config, result);
    return result;
  }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r monitor_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return monitor_(_cmd, exe_c::split_(_args), _dir, _env); }
  inline exe_r trigger_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  )
  {
    exe_c config(_cmd, _args, _dir, _env, 0, 0, 0);
    exe_r result;
    execute_(config, result);
    return result;
  }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r trigger_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return trigger_(_cmd, exe_c::split_(_args), _dir, _env); }
  static inline short run_(const exe_c& _config, exe_r& _result) { return exe_t().execute_(_config, _result); }
  static inline exe_r run_(const exe_c& _config) { return exe_t().execute_(_config); }
  static inline exe_r run_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  ) { return exe_t().execute_(_cmd, _args, _dir, _env, _timeout_ms, _capture, _period_ms); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  static inline exe_r run_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  ) { return exe_t().execute_(_cmd, exe_c::split_(_args), _dir, _env, _timeout_ms, _capture, _period_ms); }
  static inline exe_r load_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return exe_t().monitor_(_cmd, _args, _dir, _env); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  static inline exe_r load_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return exe_t().monitor_(_cmd, exe_c::split_(_args), _dir, _env); }
  static inline exe_r fire_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return exe_t().trigger_(_cmd, _args, _dir, _env); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  static inline exe_r fire_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) { return exe_t().trigger_(_cmd, exe_c::split_(_args), _dir, _env); }
private:
  inline void sample_(const exe_c& _config, exe_r& _result, int (&_stdout_pipe)[2], int (&_stderr_pipe)[2])
  {
    // 1. setup poll
    struct pollfd fds[2];
    int nfds = 0;
    if (_config.pipe_stdout_())
    {
      fds[nfds].fd = _stdout_pipe[0];
      fds[nfds].events = POLLIN;
      nfds++;
    }
    if (_config.pipe_stderr_())
    {
      fds[nfds].fd = _stderr_pipe[0];
      fds[nfds].events = POLLIN;
      nfds++;
    }
    // 2. sample loop
    char buf[page_size];
    while (true)
    {
      auto now = std::chrono::steady_clock::now();
      // 3. sample detect (before waitpid to avoid race where process exits between checks)
      uint64_t elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(now - _result.init_time).count();
      exe_p sample;
      sample.elapsed_us = elapsed_us;
      sample.state = '?';
      sample.num_threads = 0;
      exe_p_(_result.pid, sample); // this may fail if process just exited, but that's ok
      _result.samples.push_back(sample);
      // 4. check if child exited
      int status;
      pid_t pid = waitpid(_result.pid, &status, WNOHANG);
      if (pid == -1)
      {
        if (errno == EINTR) continue; // interrupted by signal
        perror("exe_t.sample_(): ---waitpid---");
        _result.status = 6; // failed
        break;
      }
      // 5. child exited
      if (pid == _result.pid)
      {
        _result.fina_time = now;
        _result.status = 3; // completed
        if (WIFEXITED(status))
        {
          _result.exit_normal = true;
          _result.exit_code = WEXITSTATUS(status);
        }
        else if (WIFSIGNALED(status))
        {
          _result.exit_normal = false;
          _result.exit_sign = WTERMSIG(status);
        }
        _result.core_dumped = WCOREDUMP(status);
        ssize_t r; // read remaining
        if (_config.pipe_stdout_())
        {
          while ((r = read(_stdout_pipe[0], buf, page_size)) > 0)
          {
            _result.stdout_info.append(buf, r);
            _result.stdout_size += r;
          }
        }
        if (_config.pipe_stderr_())
        {
          while ((r = read(_stderr_pipe[0], buf, page_size)) > 0)
          {
            _result.stderr_info.append(buf, r);
            _result.stderr_size += r;
          }
        }
        break;
      }
      // 6. timeout to kill
      if (_config.timeout_ms > 0 && !_result.timed_out)
      {
        uint64_t elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - _result.init_time).count();
        if (elapsed_ms >= _config.timeout_ms)
        {
          kill(_result.pid, SIGKILL);
          _result.timed_out = true;
        }
      }
      // 7. poll with timeout to read pipe data
      int poll_timeout = static_cast<int>(_config.period_ms);
      int ready = poll(fds, nfds, poll_timeout);
      if (ready > 0)
      {
        for (int i = 0; i < nfds; i++)
        {
          if (fds[i].revents & POLLIN)
          {
            ssize_t r = read(fds[i].fd, buf, page_size);
            if (r > 0)
            {
              if (fds[i].fd == _stdout_pipe[0]) // stdout
              {
                _result.stdout_info.append(buf, r);
                _result.stdout_size += r;
              }
              else // stderr
              {
                _result.stderr_info.append(buf, r);
                _result.stderr_size += r;
              }
            }
          }
        }
      }
    }
  }
};

/* --------------------------------------------- */