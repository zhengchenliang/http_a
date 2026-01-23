#pragma once

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <string>

/* --------------------------------------------- */

#ifndef MAX2_
#define MAX2_(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN2_
#define MIN2_(a, b) ((a) < (b) ? (a) : (b))
#endif

/* --------------------------------------------- */

struct tim_t
{
  time_t   utcs;  // seconds since epoch (UTC)
  int64_t  nsec;  // nanoseconds (0 <= nsec < 1e9)
  uint64_t utcms; // milliseconds since epoch
  uint64_t utcus; // microseconds since epoch

  tim_t() : utcs(0), nsec(0), utcms(0), utcus(0) {}

  explicit tim_t(const struct timeval& _tv)
  {
    utcs = _tv.tv_sec;
    nsec = 0;
    utcms = static_cast<uint64_t>(_tv.tv_sec) * 1000 + _tv.tv_usec / 1000;
    utcus = static_cast<uint64_t>(_tv.tv_sec) * 1000000 + _tv.tv_usec;
  }

  explicit tim_t(const struct timespec& _ts)
  {
    utcs = _ts.tv_sec;
    nsec = _ts.tv_nsec;
    utcms = static_cast<uint64_t>(_ts.tv_sec) * 1000 + _ts.tv_nsec / 1000000;
    utcus = static_cast<uint64_t>(_ts.tv_sec) * 1000000 + _ts.tv_nsec / 1000;
  }

  tim_t(uint64_t _secs, int64_t _nsec)
  {
    utcs = static_cast<time_t>(_secs);
    nsec = _nsec;
    utcms = _secs * 1000 + _nsec / 1000000;
    utcus = _secs * 1000000 + _nsec / 1000;
  }

  inline void now_()
  {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
    {
      utcs = ts.tv_sec;
      nsec = ts.tv_nsec;
      utcms = static_cast<uint64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
      utcus = static_cast<uint64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
    }
    else
    {
      utcs = time(NULL);
      nsec = 0;
      utcms = static_cast<uint64_t>(utcs) * 1000;
      utcus = static_cast<uint64_t>(utcs) * 1000000;
    }
  }

  inline std::string to_string_(const char* format = "%Y-%m-%d %H:%M:%S") const
  {
    char buffer[64];
    struct tm t;
    gmtime_r(&utcs, &t);
    size_t len = strftime(buffer, sizeof(buffer), format, &t);
    if (len > 0) return std::string(buffer);
    return std::string();
  }

  inline std::string dump_() const
  {
    char buffer[64];
    struct tm t;
    gmtime_r(&utcs, &t);
    size_t len = strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &t);
    if (len > 0 && len < sizeof(buffer) - 10)
    {
      snprintf(buffer + len, sizeof(buffer) - len, ".%09ld", nsec);
    }
    return std::string(buffer);
  }
};

/* --------------------------------------------- */

struct dat_t
{
  void* p;   // pointer
  size_t b;  // bytes

  dat_t(size_t bytes = 0) : p(NULL), b(bytes) {}
  dat_t(void* position, size_t bytes) : p(position), b(bytes) {}

  inline void fina_()
  {
    if (p)
    {
      free(p);
      p = NULL;
    }
  }

  inline short get_(const char* filename, size_t offset = 0, size_t bytes = 0) const
  {
    if (!p) return 1;
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
      perror("dat_t.get_(): ---open---");
      return -1;
    }
    flock(fd, LOCK_SH);
    struct stat fs;
    if (fstat(fd, &fs) < 0)
    {
      perror("dat_t.get_(): ---fstat---");
      flock(fd, LOCK_UN);
      close(fd);
      return -2;
    }
    size_t file_size = static_cast<size_t>(fs.st_size);
    if (offset > file_size)
    {
      fprintf(stderr, "dat_t.get_(): Read offset exceeds file size.\n");
      flock(fd, LOCK_UN);
      close(fd);
      return -3;
    }
    size_t max_bytes = file_size - offset;
    if (bytes == 0 || bytes > max_bytes) bytes = max_bytes;
    if (bytes > b)
    {
      fprintf(stderr, "dat_t.get_(): Read range exceeds buffer size.\n");
      flock(fd, LOCK_UN);
      close(fd);
      return -4;
    }
    if (pread(fd, p, bytes, offset) < 0)
    {
      perror("dat_t.get_(): ---pread---");
      flock(fd, LOCK_UN);
      close(fd);
      return -5;
    }
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
  }

  inline short put_(const char* filename, size_t offset = 0, size_t bytes = 0) const
  {
    if (!p) return 1;
    int fd = open(filename, O_WRONLY | O_CREAT, 0644);
    if (fd < 0)
    {
      perror("dat_t.put_(): ---open---");
      return -1;
    }
    flock(fd, LOCK_EX);
    struct stat fs;
    if (fstat(fd, &fs) < 0)
    {
      perror("dat_t.put_(): ---fstat---");
      flock(fd, LOCK_UN);
      close(fd);
      return -2;
    }
    size_t file_size = static_cast<size_t>(fs.st_size);
    if (offset > file_size) offset = file_size;
    if (lseek(fd, offset, SEEK_SET) < 0)
    {
      perror("dat_t.put_(): ---lseek---");
      flock(fd, LOCK_UN);
      close(fd);
      return -3;
    }
    if (bytes == 0 || bytes > b) bytes = b;
    if (write(fd, p, bytes) < 0)
    {
      perror("dat_t.put_(): ---write---");
      flock(fd, LOCK_UN);
      close(fd);
      return -4;
    }
    if (fsync(fd) < 0)
    {
      perror("dat_t.put_(): ---fsync---");
      flock(fd, LOCK_UN);
      close(fd);
      return -5;
    }
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
  }

  inline short app_(const char* filename, size_t bytes = 0) const
  {
    return put_(filename, SIZE_MAX, bytes);
  }

  inline short new_(const char* filename, size_t bytes = 0) const
  {
    unlink(filename);
    return put_(filename, 0, bytes);
  }

  inline std::string to_string_() const
  {
    if (!p || b == 0) return std::string();
    return std::string(static_cast<const char*>(p), b);
  }
};

struct dat_s : public dat_t
{
  size_t i;   // in-memory index
  uint64_t d; // on-disk offset

  dat_s(size_t bytes = 0) : dat_t(bytes), i(0), d(0) {}
  dat_s(void* position, size_t bytes, size_t inst = 0, uint64_t disk = 0)
    : dat_t(position, bytes), i(inst), d(disk) {}
};

/* --------------------------------------------- */

