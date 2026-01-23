#include "file_serve.hh"

int main(int argc, char** argv)
{

// REST Static File Server

int port = 23456;

http_a app;

// serve directory
std::string served_dir = "/root/rest/serve1/";

// static file handler (shared by GET and HEAD)
auto serve_file_ = [&](const http_q& _q, http_s& _s)
{
  // detect if HEAD request (h2o already routed by method)
  bool is_head = (_q.h2o_request
    && _q.h2o_request->method.len == 4
    && memcmp(_q.h2o_request->method.base, "HEAD", 4) == 0
  );

  // get request path using M200 API
  std::string path = _q.url_rest_();

  // url decode using M200 API (handles %20, %2E, etc.)
  std::string decoded_path = http_q::decode_(path);
  if (decoded_path.empty() && !path.empty())
  {
    _s.status_(400);
    _s.send_text_("Bad Request: Invalid URL encoding");
    return;
  }

  // security: check for null bytes (injection attack)
  if (decoded_path.find('\0') != std::string::npos)
  {
    _s.status_(400);
    _s.send_text_("Bad Request: Null byte in path");
    std::cerr << "[SECURITY] Blocked null byte injection" << std::endl;
    return;
  }

  // security: prevent directory traversal (check decoded path)
  if (decoded_path.find("..") != std::string::npos || decoded_path.find("//") != std::string::npos)
  {
    _s.status_(403);
    _s.send_text_("Forbidden: Directory traversal attempt");
    std::cerr << "[SECURITY] Blocked traversal attempt: " << decoded_path << std::endl;
    return;
  }

  // ensure path starts with /
  if (decoded_path.empty() || decoded_path[0] != '/') decoded_path = "/" + decoded_path;

  // build full path
  std::string full_path = served_dir + decoded_path.substr(1); // remove leading /

  // get canonical served_dir once (static initialization)
  static std::string canonical_served_dir = [](const std::string& _dir)
  {
    char* rp = realpath(_dir.c_str(), NULL);
    if (!rp)
    {
      std::cerr << "\n=== FATAL ERROR ===" << std::endl;
      std::cerr << "Served directory does not exist or is inaccessible:" << std::endl;
      std::cerr << "  Path: " << _dir << std::endl;
      std::cerr << "  Error: " << strerror(errno) << std::endl;
      std::cerr << "\nPlease create the directory or update the served_dir variable." << std::endl;
      std::cerr << "Example: mkdir -p " << _dir << std::endl;
      std::cerr << "==================\n" << std::endl;
      exit(1);
    }
    std::string result(rp);
    free(rp);
    if (result.back() != '/') result += "/";
    return result;
  }(served_dir);

  // try to open file with O_NOFOLLOW (no symlink follow) and O_NONBLOCK (non-blocking)
  int fd = open(full_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  bool is_dir_attempt = false;

  // if EISDIR, it's a directory - try index.html
  if (fd < 0 && errno == EISDIR)
  {
    is_dir_attempt = true;
    if (full_path.back() != '/') full_path += "/";
    full_path += "index.html";
    fd = open(full_path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  }

  // handle open failures
  if (fd < 0)
  {
    if (errno == ELOOP)
    {
      _s.status_(403);
      _s.send_text_("Forbidden: Symlinks not allowed");
      std::cerr << "[SECURITY] Blocked symlink access: " << full_path << std::endl;
    }
    else if (errno == EACCES || errno == EPERM)
    {
      _s.status_(403);
      _s.send_text_("Forbidden: Permission denied");
      std::cerr << "[SECURITY] Permission denied: " << full_path << std::endl;
    }
    else if (errno == ENOENT)
    {
      _s.status_(404);
      _s.send_text_("Not Found");
    }
    else if (errno == ENAMETOOLONG)
    {
      _s.status_(414);
      _s.send_text_("URI Too Long");
    }
    else
    {
      _s.status_(500);
      _s.send_text_("Internal Server Error");
      std::cerr << "[ERROR] open() failed for " << full_path << ": " << strerror(errno) << std::endl;
    }
    return;
  }

  // now we have an open fd - use fstat (no TOCTOU race!)
  struct stat st;
  if (fstat(fd, &st) != 0)
  {
    close(fd);
    _s.status_(500);
    _s.send_text_("Internal Server Error");
    std::cerr << "[ERROR] fstat() failed: " << strerror(errno) << std::endl;
    return;
  }

  // verify it's a regular file
  if (!S_ISREG(st.st_mode))
  {
    close(fd);
    _s.status_(403);
    _s.send_text_("Forbidden: Not a regular file");
    std::cerr << "[SECURITY] Attempt to access non-regular file: " << full_path << std::endl;
    return;
  }

  // verify canonical path is within served_dir (using /proc/self/fd for Linux)
  char fd_path[64];
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
  char* real_path = realpath(fd_path, NULL);
  if (!real_path)
  {
    close(fd);
    _s.status_(500);
    _s.send_text_("Internal Server Error");
    std::cerr << "[ERROR] realpath() on fd failed" << std::endl;
    return;
  }

  std::string canonical_path(real_path);
  free(real_path);

  // verify canonical path is within served directory
  if (canonical_path.substr(0, canonical_served_dir.size()) != canonical_served_dir)
  {
    close(fd);
    _s.status_(403);
    _s.send_text_("Forbidden: Access outside served directory");
    std::cerr << "[SECURITY] Blocked outside access: " << canonical_path
              << " (not under " << canonical_served_dir << ")" << std::endl;
    return;
  }

  // read file content using low-level read() from fd
  size_t file_size = st.st_size;
  std::string content;
  content.resize(file_size);

  ssize_t bytes_read = 0;
  ssize_t total_read = 0;
  while (total_read < static_cast<ssize_t>(file_size))
  {
    bytes_read = read(fd, &content[total_read], file_size - total_read);
    if (bytes_read < 0)
    {
      if (errno == EINTR) continue; // interrupted, retry
      close(fd);
      _s.status_(500);
      _s.send_text_("Internal Server Error: Read failed");
      std::cerr << "[ERROR] read() failed: " << strerror(errno) << std::endl;
      return;
    }
    if (bytes_read == 0) break; // EOF
    total_read += bytes_read;
  }

  close(fd);

  // adjust content size if we read less than expected
  if (total_read < static_cast<ssize_t>(file_size))
  {
    content.resize(total_read);
    file_size = total_read;
  }

  // get mime type
  std::string mime = get_mime_(canonical_path);

  // generate etag from mtime and size
  std::string etag = etag_generate_(st.st_mtime, st.st_size);

  // check if-none-match for cache validation (RFC 7232)
  if (_q.header_has_("if-none-match"))
  {
    std::string client_etag = _q.header_("if-none-match");
    if (client_etag == etag)
    {
      // 304 Not Modified: include entity headers per RFC 7232 §4.1
      _s.status_(304);
      _s.header_("Content-Type", mime); // must match original resource
      _s.header_("ETag", etag);
      _s.header_("Last-Modified", format_http_time_(st.st_mtime));
      _s.header_("Cache-Control", mime.find("text/html") == std::string::npos
        ? "public, max-age=86400"
        : "public, max-age=3600"
      );
      // send without body
      _s.body_("");
      _s.send_();
      log_request_(_q, 304, canonical_path, 0);
      return;
    }
  }

  // M200 API: status -> headers -> body -> send
  _s.status_(200);
  _s.header_("Content-Type", mime);
  _s.header_("Content-Length", std::to_string(content.size()));
  _s.header_("ETag", etag);
  _s.header_("Last-Modified", format_http_time_(st.st_mtime));

  // cache headers for static assets
  if (mime.find("text/html") == std::string::npos)
  {
    _s.header_("Cache-Control", "public, max-age=86400"); // 1 day
  }
  else
  {
    _s.header_("Cache-Control", "public, max-age=3600"); // 1 hour for html
  }

  // security headers
  _s.header_("X-Content-Type-Options", "nosniff");
  _s.header_("X-Frame-Options", "SAMEORIGIN");
  _s.header_("X-XSS-Protection", "1; mode=block");

  // fill body and send (HEAD requests get headers only, no body per RFC 7231)
  if (is_head)
  {
    // send empty body without changing Content-Type
    _s.body_("");
    _s.send_();
  }
  else
  {
    _s.body_(content);
    _s.send_();
  }

  // request logging
  log_request_(_q, 200, canonical_path, is_head ? 0 : content.size());
};

// register catch-all routes (GET and HEAD)
app.get_("/", serve_file_, true); // async serve from root
app.head_("/", serve_file_, true); // HEAD support (RFC 7231)

// listen and enable signal handling
app.listen_("127.0.0.1", port);
app.signal_(); // enable graceful shutdown on SIGINT

std::cout << "=== REST Static Server ===" << std::endl;
std::cout << "Serving: " << served_dir << std::endl;
std::cout << "Port: " << port << std::endl;
std::cout << "Ready: http://127.0.0.1:" << port << std::endl;
std::cout << "Press Ctrl+C to stop..." << std::endl;
std::cout << "" << std::endl;

// start server (blocks until signal)
app.serve_();
}
