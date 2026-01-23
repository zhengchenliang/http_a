#pragma once

#include <nlohmann/json.hpp>
#include "http_a_types.hh"
#include "http_a_thread_pool.hh"
#include "http_a_process_exec.hh"

struct http_m;
struct http_q;
struct http_g;
struct http_s;
struct http_r;

#include <cstdlib>
#include <cstddef>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <iostream>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string_view>
#include <condition_variable>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <zlib.h>
#include <brotli/decode.h>
#include <brotli/types.h>
#include <uv.h>
#include <h2o.h>
#include <h2o/http1.h>
#include <h2o/http2.h>

/* --------------------------------------------- */

inline short base64_encode_(const std::vector<uint8_t> &_data, std::string& _string) // binary to string
{
  if (_data.empty())
  {
    _string.clear();
    return 0;
  }
  BIO *b64 = BIO_new(BIO_f_base64());
  if (!b64)
  {
    fprintf(stderr, "base64_encode_() [%d]: Error creating BIO object.\n", getpid());
    return -1;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no newlines
  BIO *bmem = BIO_new(BIO_s_mem());
  if (!bmem)
  {
    fprintf(stderr, "base64_encode_() [%d]: Error creating BIO memory object.\n", getpid());
    BIO_free_all(b64);
    return -2;
  }
  b64 = BIO_push(b64, bmem);
  if (BIO_write(b64, _data.data(), _data.size()) <= 0)
  {
    fprintf(stderr, "base64_encode_() [%d]: Error writing to BIO.\n", getpid());
    BIO_free_all(b64);
    return -3;
  }
  if (BIO_flush(b64) != 1)
  {
    fprintf(stderr, "base64_encode_() [%d]: Error flushing BIO.\n", getpid());
    BIO_free_all(b64);
    return -4;
  }
  BUF_MEM *buffer_ptr = NULL;
  BIO_get_mem_ptr(b64, &buffer_ptr);
  if (!buffer_ptr || !buffer_ptr->data || buffer_ptr->length == 0)
  {
    fprintf(stderr, "base64_encode_() [%d]: Error getting memory pointer.\n", getpid());
    BIO_free_all(b64);
    return -5;
  }
  _string.assign(buffer_ptr->data, buffer_ptr->length);
  BIO_free_all(b64);
  return 0;
}
inline std::string base64_encode_(const std::vector<uint8_t> &_data)
{
  std::string result;
  if (base64_encode_(_data, result) != 0)
  {
    fprintf(stderr, "base64_encode() [%d]: Error encoding data.\n", getpid());
    return "";
  }
  return result;
}
inline short base64_decode_(const std::string &_string64, std::vector<uint8_t>& _data) // string to binary
{
  if (_string64.empty())
  {
    _data.clear();
    return 0;
  }
  BIO *b64 = BIO_new(BIO_f_base64());
  if (!b64)
  {
    fprintf(stderr, "base64_decode_() [%d]: Error creating BIO object.\n", getpid());
    return -1;
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // no newlines
  BIO *bmem = BIO_new_mem_buf(_string64.data(), _string64.size());
  if (!bmem)
  {
    fprintf(stderr, "base64_decode_() [%d]: Error creating BIO memory object.\n", getpid());
    BIO_free_all(b64);
    return -2;
  }
  b64 = BIO_push(b64, bmem);
  std::vector<uint8_t> result(EVP_DECODE_LENGTH(_string64.size()));
  int decoded_len = BIO_read(b64, result.data(), result.size());
  if (decoded_len < 0)
  {
    fprintf(stderr, "base64_decode_() [%d]: Error reading from BIO.\n", getpid());
    BIO_free_all(b64);
    return -3;
  }
  _data.assign(result.begin(), result.begin() + decoded_len);
  BIO_free_all(b64);
  return 0;
}
inline std::vector<uint8_t> base64_decode_(const std::string &_string64)
{
  std::vector<uint8_t> result;
  if (base64_decode_(_string64, result) != 0)
  {
    fprintf(stderr, "base64_decode() [%d]: Error decoding data.\n", getpid());
    return {};
  }
  return result;
}

/* --------------------------------------------- */

enum class http_b : bool { X = false, O = true }; // bool ambiguous with "char"

struct http_m // method
{
  enum value : uint8_t
  {
    NONE = 0,
    GET = 1,
    POST = 2,
    PUT = 3,
    DELETE = 4,
    PATCH = 5,
    OPTIONS = 6,
    HEAD = 7,
    TRACE = 8,
    CONNECT = 9
  };
  value v;
  constexpr http_m() noexcept : v(NONE) {}
  constexpr http_m(value val) noexcept : v(val) {}
  constexpr http_m(const char* str) noexcept : v(method_(str)) {}
  http_m(const std::string& str) noexcept : v(method_(str.c_str())) {}
  constexpr operator value() const noexcept { return v; } // use as enum e.g. http_m::GET
  explicit operator bool() = delete; // ban if(http_m)
  constexpr bool operator==(http_m other) const noexcept { return v == other.v; }
  constexpr bool operator!=(http_m other) const noexcept { return v != other.v; }
  static constexpr value method_(const char* str) noexcept
  {
    if (str[0] == 'G' && str[1] == 'E' && str[2] == 'T' && str[3] == '\0') return GET;
    if (str[0] == 'P' && str[1] == 'O' && str[2] == 'S' && str[3] == 'T' && str[4] == '\0') return POST;
    if (str[0] == 'P' && str[1] == 'U' && str[2] == 'T' && str[3] == '\0') return PUT;
    if (str[0] == 'D' && str[1] == 'E' && str[2] == 'L' && str[3] == 'E' && str[4] == 'T' && str[5] == 'E' && str[6] == '\0') return DELETE;
    if (str[0] == 'P' && str[1] == 'A' && str[2] == 'T' && str[3] == 'C' && str[4] == 'H' && str[5] == '\0') return PATCH;
    if (str[0] == 'O' && str[1] == 'P' && str[2] == 'T' && str[3] == 'I' && str[4] == 'O' && str[5] == 'N' && str[6] == 'S' && str[7] == '\0') return OPTIONS;
    if (str[0] == 'H' && str[1] == 'E' && str[2] == 'A' && str[3] == 'D' && str[4] == '\0') return HEAD;
    if (str[0] == 'T' && str[1] == 'R' && str[2] == 'A' && str[3] == 'C' && str[4] == 'E' && str[5] == '\0') return TRACE;
    if (str[0] == 'C' && str[1] == 'O' && str[2] == 'N' && str[3] == 'N' && str[4] == 'E' && str[5] == 'C' && str[6] == 'T' && str[7] == '\0') return CONNECT;
    return NONE;
  }
};
namespace std
{
  template <typename T, typename = std::enable_if_t<std::is_same_v<T, http_m>>>
  inline std::string to_string(const T m)
  {
    switch (m.v)
    {
      case http_m::GET:     return "GET";
      case http_m::POST:    return "POST";
      case http_m::PUT:     return "PUT";
      case http_m::DELETE:  return "DELETE";
      case http_m::PATCH:   return "PATCH";
      case http_m::OPTIONS: return "OPTIONS";
      case http_m::HEAD:    return "HEAD";
      case http_m::TRACE:   return "TRACE";
      case http_m::CONNECT: return "CONNECT";
      default:              return "NONE";
    }
  }
  template <>
  struct hash<http_m>
  {
    std::size_t operator()(const http_m& m) const noexcept
    {
      return static_cast<std::size_t>(m.v);
    }
  };
  template <>
  struct hash<std::pair<std::string, http_m>>
  {
    std::size_t operator()(const std::pair<std::string, http_m>& p) const noexcept
    {
      std::size_t h1 = std::hash<std::string>{}(p.first);
      std::size_t h2 = static_cast<std::size_t>(p.second.v);
      return h1 ^ (h2 * 0x9e3779b97f4a7c17ULL);
    }
  };
}
template <typename T, typename = std::enable_if_t<std::is_same_v<T, http_m>>>
inline std::ostream& operator<<(std::ostream& os, const T m)
{
  return os << std::to_string(m);
}

/* --------------------------------------------- */

using http_f = std::function<void(const http_q&, http_s&)>; // functions

struct http_q // request
{
  h2o_req_t* h2o_request = NULL;
  // A0. url
  std::string_view url; // "/api/v2/../v1/m5472/a5472?token=xxx"
  std::string_view url_normal; // "/api/v1/m5472/a5472"
  std::string_view url_prefix; // "/api/v1" registered
  std::string_view url_rest; // "/m5472/a5472"
  std::string_view url_query; // "?token=xxx" only '?' '=' '&'
  // A1. queries
  std::unordered_map<std::string_view, std::string_view> queries; // "key" = "value"
  // A2. headers
  std::unordered_map<std::string_view, std::string_view> headers; // "content-type" = "application/json" h2o already lowercased
  // A3. metadata
  int http_vers; // HTTP version = 0xMMmm
  std::string_view http_auth; // host header value
  struct timeval http_time[2]; // request_begin_at, request_body_begin_at
  // A4. body
  std::string_view body; // request entity/body
  size_t size; // request entity/body size
  dat_t data; // request entity/body data
  // C0. url
  static inline std::string version_(int _version) noexcept
  {
    const int major = (_version >> 8) & 0xFF;
    const int minor = _version & 0xFF;
    return std::string("HTTP/") + std::to_string(major) + "." + std::to_string(minor);
  }
  static inline int decode_hex_(int _ch) noexcept
  {
    if ('0' <= _ch && _ch <= '9') return _ch - '0';
    if ('A' <= _ch && _ch <= 'F') return _ch - 'A' + 0xa;
    if ('a' <= _ch && _ch <= 'f') return _ch - 'a' + 0xa;
    return -1;
  }
  static inline std::string decode_(std::string_view _encoded)
  {
    std::string decoded;
    decoded.reserve(_encoded.size());
    for (size_t i = 0; i < _encoded.size(); ++i)
    {
      if (_encoded[i] == '%')
      {
        if (i + 2 >= _encoded.size())
        {
          fprintf(stderr, "http_q.decode_() [%d]: Invalid encoding %s\n", getpid(), _encoded.data());
          return "";
        }
        int hi = decode_hex_(_encoded[i + 1]);
        int lo = decode_hex_(_encoded[i + 2]);
        if (hi < 0 || lo < 0 || (hi == 0 && lo == 0))
        {
          fprintf(stderr, "http_q.decode_() [%d]: Invalid hex digits %s\n", getpid(), _encoded.data());
          return "";
        }
        decoded.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
      }
      else decoded.push_back(_encoded[i]);
    }
    return decoded;
  }
  static inline std::string encode_(std::string_view _decoded, const char* _preserve_chars = NULL)
  {
    std::string encoded;
    encoded.reserve(_decoded.size() * 3 + 1);
    for (size_t i = 0; i < _decoded.size(); ++i) // RFC 3986
    {
      int ch = static_cast<unsigned char>(_decoded[i]);
      if (('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9')
        || ch == '-' || ch == '.' || ch == '_' || ch == '~' || ch == '!'
        || ch == '$' || ch == '&' || ch == '\'' || ch == '(' || ch == ')'
        || ch == '*' || ch == '+' || ch == ',' || ch == ';' || ch == '='
        || (ch != '\0' && _preserve_chars != NULL && strchr(_preserve_chars, ch) != NULL)
      ) encoded.push_back(static_cast<char>(ch));
      else
      {
        encoded.push_back('%');
        encoded.push_back("0123456789ABCDEF"[(ch >> 4) & 0xf]);
        encoded.push_back("0123456789ABCDEF"[ch & 0xf]);
      }
    }
    return encoded;
  }
  http_q(h2o_req_t* _h2o_request) { init_(_h2o_request); }
  inline void init_(h2o_req_t* _h2o_request)
  {
    h2o_request = _h2o_request;
    url_(_h2o_request);
    queries_(_h2o_request);
    headers_(_h2o_request);
    metadata_();
    body_();
  }
  // Z0. url
  inline void url_(h2o_req_t* _h2o_request)
  {
    this->url = std::string_view(_h2o_request->path.base, _h2o_request->path.len);
    this->url_normal = std::string_view(_h2o_request->path_normalized.base, _h2o_request->path_normalized.len);
    this->url_prefix = std::string_view(_h2o_request->pathconf->path.base, _h2o_request->pathconf->path.len);
    this->url_rest = url_normal.substr(url_prefix.size());
    this->url_query = (_h2o_request->query_at != SIZE_MAX)
      ? std::string_view(_h2o_request->path.base + _h2o_request->query_at, _h2o_request->path.len - _h2o_request->query_at)
      : std::string_view()
    ;
  }
  inline std::string url_() const { return std::string(url); }
  inline std::string url_normal_() const { return std::string(url_normal); }
  inline std::string url_prefix_() const { return std::string(url_prefix); }
  inline std::string url_rest_() const { return std::string(url_rest); }
  inline std::string url_query_() const { return std::string(url_query); }
  inline std::string rest_raw_() const // rest only with "/": subpath; "?": query; "": end
  {
    if (url_rest.empty()) return std::string(url_query);
    else // with subpath
    {
      size_t prefix_len = url_prefix.size();
      size_t raw_start;
      if (h2o_request->norm_indexes != NULL && prefix_len < url_normal.size())
      {
        raw_start = h2o_request->norm_indexes[prefix_len];
        if (raw_start < url.size() && url[raw_start] != '/' && url_rest[0] == '/')
        {
          if (raw_start > 0) raw_start--; // include the '/'
        }
      }
      else
      {
        raw_start = prefix_len;
        if (raw_start < url.size() && url[raw_start] != '/' && url_rest[0] == '/')
        {
          if (raw_start > 0) raw_start--; // include the '/'
        }
      }
      if (raw_start >= url.size()) return std::string();
      return std::string(url.substr(raw_start));
    }
  }
  // Z1. queries
  inline void queries_(h2o_req_t* _h2o_request) // ?cmd=env&args=&env=SDK=1.7|PATH=/usr/bin|VERS=1.0&fuk=you
  {
    queries.clear();
    queries.reserve(8);
    std::string_view _url_query = _h2o_request ? url_query : std::string_view();
    if (_url_query.empty() || _url_query[0] != '?') return;
    _url_query.remove_prefix(1);
    size_t start = 0;
    while (start < _url_query.size())
    {
      size_t eq_pos = _url_query.find('=', start); // the first '='
      if (eq_pos == std::string_view::npos) break; // no more key=value
      size_t amp_pos = _url_query.find('&', eq_pos + 1);
      std::string_view key = _url_query.substr(start, eq_pos - start);
      std::string_view value = (amp_pos == std::string_view::npos)
        ? _url_query.substr(eq_pos + 1)
        : _url_query.substr(eq_pos + 1, amp_pos - eq_pos - 1)
      ;
      queries.emplace(key, value);
      if (amp_pos == std::string_view::npos) break;
      start = amp_pos + 1;
    }
  }
  inline std::unordered_map<std::string, std::string> queries_() const
  {
    std::unordered_map<std::string, std::string> result;
    result.reserve(queries.size());
    for (const auto& [key, value] : queries)
    {
      result.emplace(std::string(key), std::string(value));
    }
    return result;
  }
  inline std::string query_(std::string_view _key) const
  {
    auto it = queries.find(_key);
    if (it != queries.end()) return std::string(it->second);
    return "";
  }
  inline bool query_has_(std::string_view _key) const
  {
    return queries.find(_key) != queries.end();
  }
  inline std::unordered_map<std::string, std::string> expand_(const std::string& _env_str) const // SDK=1.7|PATH=/usr/bin|VERS=1.0
  {
    std::unordered_map<std::string, std::string> result;
    result.reserve(8);
    size_t start = 0;
    while (start < _env_str.size())
    {
      size_t sep = _env_str.find('|', start);
      std::string_view part = (sep == std::string::npos)
        ? std::string_view(_env_str).substr(start)
        : std::string_view(_env_str).substr(start, sep - start)
      ;
      if (!part.empty())
      {
        size_t eq = part.find('=');
        if (eq != std::string_view::npos && eq > 0)
        {
          std::string key(part.substr(0, eq));
          std::string val(part.substr(eq + 1));
          result.emplace(std::move(key), std::move(val));
        }
      }
      if (sep == std::string::npos) break;
      start = sep + 1;
    }
    return result;
  }
  // Z2. headers
  inline void headers_(h2o_req_t* _h2o_request)
  {
    headers.clear();
    headers.reserve(_h2o_request->headers.size);
    for (size_t i = 0; i < _h2o_request->headers.size; ++i)
    {
      const auto& h = _h2o_request->headers.entries[i];
      std::string_view key(h.name->base, h.name->len);
      std::string_view value(h.value.base, h.value.len);
      headers.emplace(key, value);
    }
  }
  inline std::unordered_map<std::string, std::string> headers_() const
  {
    std::unordered_map<std::string, std::string> result;
    result.reserve(headers.size());
    for (const auto& [key, value] : headers)
    {
      result.emplace(std::string(key), std::string(value));
    }
    return result;
  }
  inline std::string header_(std::string_view _key) const
  {
    auto it = headers.find(_key);
    if (it != headers.end()) return std::string(it->second.data(), it->second.size());
    return std::string();
  }
  inline bool header_has_(std::string_view _key) const
  {
    return headers.find(_key) != headers.end();
  }
  // Z3. metadata
  inline void metadata_()
  {
    if (!h2o_request) return;
    http_vers = h2o_request->version;
    http_auth = std::string_view(h2o_request->input.authority.base, h2o_request->input.authority.len);
    http_time[0] = h2o_request->timestamps.request_begin_at;
    http_time[1] = h2o_request->timestamps.request_body_begin_at;
  }
  inline int vers_() const { return http_vers; }
  inline std::string http_vers_() const { return version_(http_vers); }
  inline std::string http_auth_() const { return std::string(http_auth); }
  inline tim_t http_time_0_() const { return tim_t(http_time[0]); }
  inline tim_t http_time_1_() const { return tim_t(http_time[1]); }
  // Z4. body
  inline void body_()
  {
    size = h2o_request->entity.len;
    if (size == SIZE_MAX) size = 0;
    body = h2o_request->entity.base
      ? std::string_view(h2o_request->entity.base, size)
      : std::string_view()
    ;
    data = dat_t(h2o_request->entity.base, size);
  }
  inline short body_(dat_s* _data) const
  {
    if (!_data->p) // new data
    {
      _data->b = size;
      _data->p = malloc(_data->b);
      if (!_data->p)
      {
        perror("http_q.body_(): ---malloc---");
        return -4;
      }
    }
    else // existing data
    {
      if (_data->b != size)
      {
        try { free(_data->p); } catch (...) {}
        _data->b = size;
        _data->p = malloc(_data->b);
        if (!_data->p)
        {
          perror("http_q.body_(): ---malloc---");
          return -5;
        }
      }
    }
    memcpy(_data->p, data.p, size);
    return 0;
  }
  // EXE
  inline exe_r exe_run_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  ) const { return exe_t().execute_(_cmd, _args, _dir, _env, _timeout_ms, _capture, _period_ms); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r exe_run_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
    , uint64_t _timeout_ms = 0
    , uint8_t _capture = 0
    , uint64_t _period_ms = 0
  ) const { return exe_t().execute_(_cmd, exe_c::split_(_args), _dir, _env, _timeout_ms, _capture, _period_ms); }
  inline exe_r exe_load_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) const { return exe_t().monitor_(_cmd, _args, _dir, _env); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r exe_load_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) const { return exe_t().monitor_(_cmd, exe_c::split_(_args), _dir, _env); }
  inline exe_r exe_fire_(const std::string& _cmd
    , const std::vector<std::string>& _args = {}
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) const { return exe_t().trigger_(_cmd, _args, _dir, _env); }
  template <typename T
    , typename = std::enable_if_t<std::is_same_v<T, std::string>
      || std::is_same_v<std::decay_t<T>, char*>
    >
  >
  inline exe_r exe_fire_(const std::string& _cmd
    , const T& _args = ""
    , const std::string& _dir = ""
    , const std::unordered_map<std::string, std::string>& _env = {}
  ) const { return exe_t().trigger_(_cmd, exe_c::split_(_args), _dir, _env); }
  // DAT
  inline short dat_put_(const std::string& filepath, size_t offset = 0) const
  {
    return data.put_(filepath.c_str(), offset, data.b);
  }
  inline short dat_app_(const std::string& filepath) const
  {
    return data.app_(filepath.c_str(), data.b);
  }
  inline short dat_new_(const std::string& filepath) const
  {
    return data.new_(filepath.c_str(), data.b);
  }
};

struct http_g // generator
{
  h2o_generator_t super;
  h2o_req_t* req;
  h2o_timer_t timer;
  uv_async_t notify;
  dat_t body_data;
  http_b body_h2o; // on h2o memory pool
  std::mutex body_mutex;
  std::atomic<bool> sent{false};
  std::atomic<bool> completed{false};
  std::atomic<bool> is_failing{false};
  std::atomic<bool> is_timeout{false};
  static inline void on_notify_(uv_async_t* _notify)
  {
    auto* generator = H2O_STRUCT_FROM_MEMBER(http_g, notify, _notify);
    proceed_(&generator->super, generator->req);
  }
  static inline void on_timeout_(h2o_timer_t* _entry)
  {
    auto* generator = H2O_STRUCT_FROM_MEMBER(http_g, timer, _entry);
    if (!generator->completed)
    {
      {
        std::lock_guard<std::mutex> lock(generator->body_mutex);
        generator->body_data = dat_t(NULL, 0);
      }
      generator->completed.store(true);
      generator->is_failing.store(true);
      generator->is_timeout.store(true);
      proceed_(&generator->super, generator->req);
    }
  }
  static inline void proceed_(h2o_generator_t* _self, h2o_req_t* _req)
  {
    auto* generator = reinterpret_cast<http_g*>(_self);
    if (h2o_timer_is_linked(&generator->timer)) h2o_timer_unlink(&generator->timer);
    if (uv_is_active((uv_handle_t*)&generator->notify)) uv_close((uv_handle_t*)&generator->notify, NULL);
    bool expected = false;
    if (!generator->sent.compare_exchange_strong(expected, true))
    {
      h2o_iovec_t body = h2o_iovec_init(NULL, 0);
      _req->res.status = 410;
      _req->res.reason = "Already Sent";
      h2o_send(_req
        , &body
        , 1
        , H2O_SEND_STATE_FINAL
      );
      generator->~http_g();
      return;
    }
    if (generator->completed.load())
    {
      h2o_iovec_t body = h2o_iovec_init(NULL, 0);
      if (generator->is_timeout.load())
      {
        _req->res.status = 504;
        _req->res.reason = "Gateway Timeout";
      }
      else if (generator->is_failing.load())
      {
        _req->res.status = 500;
        _req->res.reason = "Execute Failure";
      }
      else
      {
        if (_req->res.status == 0) _req->res.status = 200;
        std::lock_guard<std::mutex> lock(generator->body_mutex);
        if (generator->body_h2o == http_b::O) body = h2o_iovec_init(generator->body_data.p, generator->body_data.b); // already in h2o memory pool
        else body = h2o_strdup(&_req->pool, static_cast<const char*>(generator->body_data.p), generator->body_data.b);
      }
      h2o_send(_req
        , &body
        , 1
        , H2O_SEND_STATE_FINAL
      );
      generator->~http_g(); // RFC 7230/9112: at <connection, close> the client must close tcp socket
    }
  }
  static void stop_(h2o_generator_t* _self, h2o_req_t* _req)
  {
    auto* generator = reinterpret_cast<http_g*>(_self);
    if (h2o_timer_is_linked(&generator->timer)) h2o_timer_unlink(&generator->timer);
    if (uv_is_active((uv_handle_t*)&generator->notify)) uv_close((uv_handle_t*)&generator->notify, NULL);
  }
};

struct http_s // response
{ // all async persistent
  h2o_req_t* h2o_request = NULL;
  dat_t data;
  bool async;
  http_g* async_gen = NULL;
  // R1. status
  inline void status_(int _code, const std::string& _reason = "") // response status: 200, "OK"
  {
    h2o_request->res.status = _code;
    h2o_request->res.reason = _reason.empty()
      ? (_code == 200 ? "OK"
        : _code == 201 ? "Created"
        : _code == 202 ? "Accepted"
        : _code == 203 ? "Non-Authoritative Information"
        : _code == 204 ? "No Content"
        : _code == 205 ? "Reset Content"
        : _code == 206 ? "Partial Content"
        : _code == 207 ? "Multi-Status"
        : _code == 208 ? "Already Reported"
        : _code == 226 ? "IM Used"
        : _code == 300 ? "Multiple Choices"
        : _code == 301 ? "Moved Permanently"
        : _code == 302 ? "Found"
        : _code == 303 ? "See Other"
        : _code == 304 ? "Not Modified"
        : _code == 305 ? "Use Proxy"
        : _code == 306 ? "Switch Proxy"
        : _code == 307 ? "Temporary Redirect"
        : _code == 308 ? "Permanent Redirect"
        : _code == 400 ? "Bad Request"
        : _code == 401 ? "Unauthorized"
        : _code == 403 ? "Forbidden"
        : _code == 404 ? "Not Found"
        : _code == 405 ? "Method Not Allowed"
        : _code == 406 ? "Not Acceptable"
        : _code == 408 ? "Request Timeout"
        : _code == 409 ? "Conflict"
        : _code == 410 ? "Gone"
        : _code == 411 ? "Length Required"
        : _code == 412 ? "Precondition Failed"
        : _code == 500 ? "Internal Server Error"
        : _code == 501 ? "Not Implemented"
        : _code == 502 ? "Bad Gateway"
        : _code == 503 ? "Service Unavailable"
        : _code == 504 ? "Gateway Timeout"
        : _code == 505 ? "HTTP Version Not Supported"
        : _code == 506 ? "Variant Also Negotiates"
        : _code == 507 ? "Insufficient Storage"
        : _code == 508 ? "Loop Detected"
        : _code == 510 ? "Not Extended"
        : "")
      : _reason.c_str()
    ;
  }
  // R2. headers
  inline void header_(const std::string& _name, const std::string& _value) // any header: "Content-Type", "application/json"
  {
    h2o_iovec_t rcy_name = h2o_strdup(&h2o_request->pool, _name.data(), _name.size());
    h2o_iovec_t rcy_value = h2o_strdup(&h2o_request->pool, _value.data(), _value.size());
    std::string lc_name = _name;
    std::transform(lc_name.begin(), lc_name.end(), lc_name.begin(), ::tolower); // to lower case
    h2o_iovec_t rcy_lc_name = h2o_strdup(&h2o_request->pool, lc_name.data(), lc_name.size());
    h2o_add_header_by_str(&h2o_request->pool
      , &h2o_request->res.headers
      , rcy_lc_name.base
      , rcy_lc_name.len
      , 1 // maybe_token: try to find token first
      , rcy_name.base
      , rcy_value.base
      , rcy_value.len
    ); // h2o has a pseudo-trie for the lookup
  }
  template <typename MapType = std::unordered_map<std::string, std::string>
    , typename = std::enable_if_t<std::is_convertible_v<typename MapType::key_type, std::string>
      && std::is_convertible_v<typename MapType::mapped_type, std::string>
    >
  >
  inline void header_(const MapType& _headers)
  {
    for (const auto& [key, value] : _headers)
    {
      header_(key, value);
    }
  }
  inline void header_text_(const std::string& _charset = "utf-8")
  {
    std::string value = "text/plain; charset=" + _charset;
    h2o_iovec_t rcy_value = h2o_strdup(&h2o_request->pool, value.data(), value.size());
    h2o_add_header(&h2o_request->pool
      , &h2o_request->res.headers
      , H2O_TOKEN_CONTENT_TYPE
      , NULL
      , rcy_value.base
      , rcy_value.len
    );
  }
  inline void header_html_(const std::string& _charset = "utf-8")
  {
    std::string value = "text/html; charset=" + _charset;
    h2o_iovec_t rcy_value = h2o_strdup(&h2o_request->pool, value.data(), value.size());
    h2o_add_header(&h2o_request->pool
      , &h2o_request->res.headers
      , H2O_TOKEN_CONTENT_TYPE
      , NULL
      , rcy_value.base
      , rcy_value.len
    );
  }
  inline void header_json_(const std::string& _charset = "utf-8")
  {
    std::string value = "application/json; charset=" + _charset;
    h2o_iovec_t rcy_value = h2o_strdup(&h2o_request->pool, value.data(), value.size());
    h2o_add_header(&h2o_request->pool
      , &h2o_request->res.headers
      , H2O_TOKEN_CONTENT_TYPE
      , NULL
      , rcy_value.base
      , rcy_value.len
    );
  }
  // R3. policy
  inline void stay_() // force keep-alive: HTTP/1.0 default is quit
  {
    h2o_request->http1_is_persistent = 1;
  }
  inline void quit_() // force quit: HTTP/1.1 default is keep-alive
  {
    h2o_request->http1_is_persistent = 0;
  }
  // R4. body
  inline void body_(dat_t* _data)
  {
    data = dat_t(_data->p, _data->b);
  }
  inline void body_(const dat_t& _data)
  {
    data = dat_t(_data.p, _data.b);
  }
  inline void body_(const std::string& _string)
  {
    data = dat_t(const_cast<char*>(_string.data()), _string.size());
  }
  // R5. send
  inline void send_(http_b _h2o = http_b::X) { send_(&data, _h2o); }
  inline void send_(dat_t* _data, http_b _h2o = http_b::X)
  {
    if (async)
    {
      std::lock_guard<std::mutex> lock(async_gen->body_mutex);
      if (_h2o == http_b::O) // already in h2o memory pool
      {
        async_gen->body_data = *_data;
        async_gen->body_h2o = http_b::O;
      }
      else
      {
        void* buffer = h2o_mem_alloc_pool(&h2o_request->pool, char, _data->b);
        if (!buffer) throw std::runtime_error(std::string("http_s.send_(): Failed to h2o_mem_alloc_pool() for ") + std::to_string(_data->b) + " bytes.");
        memcpy(buffer, _data->p, _data->b);
        async_gen->body_data = dat_t(static_cast<char*>(buffer), _data->b);
        async_gen->body_h2o = http_b::O;
      }
    }
    else
    {
      if (h2o_request->res.status == 0) status_(200);
      h2o_iovec_t body;
      if (_h2o == http_b::O) body = h2o_iovec_init(_data->p, _data->b); // already in h2o memory pool
      else body = h2o_strdup(&h2o_request->pool, static_cast<const char*>(_data->p), _data->b);
      static h2o_generator_t sync_gen = {NULL, NULL};
      h2o_start_response(h2o_request, &sync_gen);
      h2o_send(h2o_request
        , &body
        , 1
        , H2O_SEND_STATE_FINAL
      );
    }
  }
  inline void send_(dat_t& _data, http_b _h2o = http_b::X) { send_(&_data, _h2o); }
  inline void send_(const std::string& _string, http_b _h2o = http_b::X) { body_(_string); send_(_h2o); }
  inline void send_text_(http_b _h2o = http_b::X) { header_text_(); send_(_h2o); }
  inline void send_text_(dat_t* _data, http_b _h2o = http_b::X) { header_text_(); body_(_data); send_(_h2o); }
  inline void send_text_(dat_t& _data, http_b _h2o = http_b::X) { header_text_(); body_(_data); send_(_h2o); }
  inline void send_text_(const std::string& _string, http_b _h2o = http_b::X) { header_text_(); body_(_string); send_(_h2o); }
  inline void send_html_(http_b _h2o = http_b::X) { header_html_(); send_(_h2o); }
  inline void send_html_(dat_t* _data, http_b _h2o = http_b::X) { header_html_(); body_(_data); send_(_h2o); }
  inline void send_html_(dat_t& _data, http_b _h2o = http_b::X) { header_html_(); body_(_data); send_(_h2o); }
  inline void send_html_(const std::string& _string, http_b _h2o = http_b::X) { header_html_(); body_(_string); send_(_h2o); }
  inline void send_json_(http_b _h2o = http_b::X) { header_json_(); send_(_h2o); }
  inline void send_json_(dat_t* _data, http_b _h2o = http_b::X) { header_json_(); body_(_data); send_(_h2o); }
  inline void send_json_(dat_t& _data, http_b _h2o = http_b::X) { header_json_(); body_(_data); send_(_h2o); }
  inline void send_json_(const std::string& _string, http_b _h2o = http_b::X) { header_json_(); body_(_string); send_(_h2o); }
  inline void send_json_(const nlohmann::json& _j, http_b _h2o = http_b::X) { send_json_(_j.dump(), _h2o); }
  // DAT
  inline short dat_get_(const std::string& filepath, size_t offset = 0, size_t bytes = 0) // send_(http_b::O)
  {
    struct stat st;
    if (stat(filepath.c_str(), &st) != 0)
    {
      perror("http_s.dat_get_(): ---stat---");
      return -1;
    }
    size_t file_size = st.st_size;
    if (bytes == 0 || bytes > file_size - offset) bytes = file_size - offset;
    void* buffer = h2o_mem_alloc_pool(&h2o_request->pool, char, bytes);
    if (!buffer)
    {
      fprintf(stderr, "http_s.dat_get_(): Failed to h2o_mem_alloc_pool() for %zu bytes.\n", bytes);
      return -2;
    }
    dat_t buffer_dat(buffer, bytes);
    short result = buffer_dat.get_(filepath.c_str(), offset, bytes);
    if (result == 0) data = buffer_dat;
    return result;
  }
};

class http_a // http_a app -> app.ssl_() -> app.register_()/listen_()/signal_() -> app.start_()/thread.serve_() -> app.stop_() -> app.register_()/listen_()/signal_() -> app.start_()/thread.serve_() -> ~()
{ // async: register_() -> on_req_() -> business_() -> send_() -> proceed_() -> ~http_g()
public:
  struct http_h : public h2o_handler_t // handler
  {
    std::string method;
    http_f business_;
    bool async;
    uint64_t timeout_ms;
    http_a* app;
    static inline int on_req_(h2o_handler_t* _self, h2o_req_t* _req) // h2o callback signature
    {
      auto* handler = static_cast<http_h*>(_self);
      if (!h2o_memis(_req->method.base
        , _req->method.len
        , handler->method.data()
        , handler->method.size())
      ) return -1; // method mismatch -> h2o continue to next handler
      if (handler->async) // async deal
      {
        void* buffer = h2o_mem_alloc_pool(&_req->pool, char, sizeof(http_g));
        if (!buffer)
        {
          fprintf(stderr, "http_a.on_req_(): Failed to h2o_mem_alloc_pool() for %zu bytes.\n", sizeof(http_g));
          return -2;
        }
        http_g* generator = new(buffer) http_g(); // h2o_req_t* alive before generator disposed
        generator->super.proceed = http_g::proceed_;
        generator->super.stop = http_g::stop_;
        generator->req = _req;
        h2o_timer_init(&generator->timer, http_g::on_timeout_);
        if (handler->timeout_ms > 0) h2o_timer_link(_req->conn->ctx->loop, handler->timeout_ms, &generator->timer);
        uv_async_init(_req->conn->ctx->loop, &generator->notify, http_g::on_notify_); // is my loop
        generator->notify.data = generator;
        h2o_start_response(_req, &generator->super);
        h2o_req_t* req_ptr = _req;
        handler->app->pthd.fire_(
          [generator, req_ptr, business_ = handler->business_]() mutable
          {
            try
            {
              http_q q{req_ptr};
              http_s s{req_ptr, {NULL, 0}, true};
              s.async_gen = generator;
              business_(q, s);
              generator->completed.store(true);
              generator->is_failing.store(false);
              generator->is_timeout.store(false);
              uv_async_send(&generator->notify);
            }
            catch (...)
            {
              generator->completed.store(true);
              generator->is_failing.store(true);
              generator->is_timeout.store(false);
              uv_async_send(&generator->notify);
            }
          }
        );
      }
      else // sync deal
      {
        try
        {
          http_q q{_req};
          http_s s{_req, {NULL, 0}, false};
          handler->business_(q, s);
        }
        catch (const std::exception& e)
        {
          http_s s{_req, {NULL, 0}, false};
          s.status_(500, "Execute Failure");
          s.send_(e.what());
          return 0;
        }
        catch (...)
        {
          http_s s{_req, {NULL, 0}, false};
          s.status_(500, "Execute Failure");
          s.send_("Unknown Error");
          return 0;
        }
      }
      return 0;
    }
    static inline void dispose_(h2o_handler_t* _self) // h2o dispose signature: called when handler is destroyed
    {
      auto* handler = static_cast<http_h*>(_self);
      handler->~http_h();
    }
  };
  pth_t pthd;                          // server thread pool
  std::atomic<uint8_t> state;          // 0 = finalized; 1 = initialized; 2 = serving; 3 = stopped;
  std::thread server_t;                // server thread
  std::atomic<bool> server_a;          // true = thread server alive
  std::atomic<bool> server_r;          // true = server does restart
  std::mutex server_m;                 // server mutex
  std::condition_variable server_c;    // server condition variable
  uv_loop_t loop;                      // uv event loop
  uv_async_t loop_a;                   // uv async sender
  uv_timer_t loop_t;                   // uv loop timer
  std::vector<uv_tcp_t*> listeners;    // uv listeners
  std::vector<uv_signal_t*> signalers; // uv signalers
  h2o_globalconf_t gconfig;            // h2o global configuration
  h2o_hostconf_t* hconfig = NULL;      // h2o host configuration
  h2o_hostconf_t* hconfig_a[2];        // h2o hosts configuration
  h2o_context_t ctx;                   // h2o context (per-thread)
  h2o_accept_ctx_t accept_ctx;         // h2o accept context for new connections
  SSL_CTX* ssl_ctx = NULL;             // openssl ssl context
  std::chrono::steady_clock::time_point start_time; // server start time
  struct prefix_c
  {
    h2o_pathconf_t* pathconf;
    std::unordered_map<http_m, http_h*> handlers; // <method, handler>
    prefix_c() : pathconf(NULL) { handlers.reserve(10); }
    prefix_c(h2o_pathconf_t* _pathconf) : pathconf(_pathconf) { handlers.reserve(10); }
    ~prefix_c() { handlers.clear(); }
  };
  std::unordered_map<std::string, prefix_c> prefix_groups; // <prefix, prefix_c>
  http_a()
  {
    state.store(0);
    server_a.store(false);
    server_r.store(false);
    init_();
  }
  ~http_a() { fina_(); }
  http_a(const http_a&) = delete;
  http_a& operator=(const http_a&) = delete;
  http_a(http_a&&) = delete;
  http_a& operator=(http_a&&) = delete;
  inline void init_()
  {
    if (state.load() != 0) return; // already initialized or serving or stopped
    pthd.rebn_(MIN2_(4096, MAX2_(1, sysconf(_SC_NPROCESSORS_ONLN)) * 2));
    // 1. setup uv event loop with sender and timer
    uv_loop_init(&loop); // uv event loop local
    uv_async_init(&loop, &loop_a, [](uv_async_t* handle) {});
    uv_timer_init(&loop, &loop_t);
    loop_a.data = this;
    loop_t.data = this;
    // 2. setup h2o global configuration
    h2o_config_init(&gconfig);
    h2o_compress_register_configurator(&gconfig);
    // 3. setup h2o host configuration
    hconfig = h2o_config_register_host(&gconfig
      , h2o_iovec_init(H2O_STRLIT("default"))
      , 65535 // h2o http server at
    );
    // 4. initialize h2o context
    h2o_context_init(&ctx, &loop, &gconfig); // ctx.loop = loop
    // 5. setup accept context
    hconfig_a[0] = hconfig;
    hconfig_a[1] = NULL;
    accept_ctx.hosts = hconfig_a;
    accept_ctx.ctx = &ctx;
    accept_ctx.ssl_ctx = ssl_ctx;
    state.store(1);
  }
  inline void ssl_(const std::string& _cert_file, const std::string& _key_file) // setup at initialized
  {
    if (state.load() != 1) return; // finalized or serving or stopped: one port 80/443 one http(s) protocol
    if (ssl_ctx) // switch ssl cert/key
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
    }
    else // for ancient openssl version
    {
      // 0. initialize openssl
      SSL_library_init();
      SSL_load_error_strings();
      OpenSSL_add_all_algorithms();
    }
    // 1. create ssl context
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx)
    {
      throw std::runtime_error("http_a.ssl_(): Failed to create SSL context w/ " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // 2. load certificate
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, _cert_file.c_str()) != 1)
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
      throw std::runtime_error("http_a.ssl_(): Failed to load certificate: " + _cert_file + " w/ " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // 3. load private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, _key_file.c_str(), SSL_FILETYPE_PEM) != 1)
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
      throw std::runtime_error("http_a.ssl_(): Failed to load private key: " + _key_file + " w/ " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // 4. verify key matches certificate
    if (SSL_CTX_check_private_key(ssl_ctx) != 1)
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
      throw std::runtime_error("http_a.ssl_(): Private key " + _key_file + " does not match certificate " + _cert_file + " w/ " + std::string(ERR_error_string(ERR_get_error(), NULL)));
    }
    // 5. set ssl options
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    // 6. update h2o accept context
    accept_ctx.ssl_ctx = ssl_ctx;
  }
  static inline void on_accept_(uv_stream_t* _listener, int _status) // uv ip:port listener callback signature: called when connection comes at its ip:port
  {
    if (_status != 0) return;
    // 1. uv create connection handle for h2o http server
    uv_tcp_t* conn = new uv_tcp_t; // uv -> h2o client(connection) tcp -> http socket
    uv_tcp_init(_listener->loop, conn);
    // 2. uv accept coming connection
    if (uv_accept(_listener, reinterpret_cast<uv_stream_t*>(conn)) != 0)
    {
      uv_close(reinterpret_cast<uv_handle_t*>(conn)
        , [](uv_handle_t* handle) { delete reinterpret_cast<uv_tcp_t*>(handle); }
      );
      return;
    }
    // 3. h2o get its accept context of that listener
    auto* acc_ctx = static_cast<h2o_accept_ctx_t*>(_listener->data);
    // 4. h2o create socket from connection handle (uv -> h2o upgrade)
    h2o_socket_t* sock = h2o_uv_socket_create(reinterpret_cast<uv_handle_t*>(conn)
      , [](uv_handle_t* handle) { delete reinterpret_cast<uv_tcp_t*>(handle); }
    );
    // 5. h2o accept connection socket
    h2o_accept(acc_ctx, sock);
  }
  inline void listen_(const std::string& _host = "0.0.0.0", uint16_t _port = 8080)
  {
    if (state.load() % 2 != 1) return; // finalized or serving
    // 1. uv create ip:port listener handle
    uv_tcp_t* listener = new uv_tcp_t;
    uv_tcp_init(&loop, listener);
    // 2. uv record h2o accept_ctx in listener
    listener->data = &accept_ctx;
    // 3. uv socket bind to ip:port
    struct sockaddr_in addr;
    uv_ip4_addr(_host.c_str(), _port, &addr);
    int r = uv_tcp_bind(listener, reinterpret_cast<struct sockaddr*>(&addr), 0); // uv ip:port socket bind
    if (r != 0)
    {
      uv_close(reinterpret_cast<uv_handle_t*>(listener)
        , [](uv_handle_t* handle) { delete reinterpret_cast<uv_tcp_t*>(handle); }
      );
      throw std::runtime_error("http_a.listen_(): Failed to bind to " + _host + ":" + std::to_string(_port) + " w/ " + uv_strerror(r));
    }
    // 4. uv start listening
    r = uv_listen(reinterpret_cast<uv_stream_t*>(listener), 128, on_accept_); // uv socket set on event loop
    if (r != 0)
    {
      uv_close(reinterpret_cast<uv_handle_t*>(listener)
        , [](uv_handle_t* handle) { delete reinterpret_cast<uv_tcp_t*>(handle); }
      );
      throw std::runtime_error("http_a.listen_(): Failed to listen on " + _host + ":" + std::to_string(_port) + " w/ " + uv_strerror(r));
    }
    // 5. uv manage listeners in STL
    listeners.push_back(listener);
  }
  inline void delisten_()
  {
    for (auto* listener : listeners)
    {
      uv_read_stop(reinterpret_cast<uv_stream_t*>(listener));
      if (uv_is_closing(reinterpret_cast<uv_handle_t*>(listener)) == 0) uv_close(reinterpret_cast<uv_handle_t*>(listener)
        , [](uv_handle_t* handle) { delete reinterpret_cast<uv_tcp_t*>(handle); }
      );
    }
    listeners.clear();
    uv_async_send(&loop_a); // sender acknoledge for last pending listener events
  }
  static inline void on_signal_(uv_signal_t* _sig, int _signum)
  {
    auto* self = static_cast<http_a*>(_sig->data);
    printf("\nhttp_a.signal_() [%d]: Caught signal %d stopping loop ...\n", getpid(), _signum);
    self->stop_(); // graceful stop on signals
  }
  inline void signal_()
  {
    if (state.load() % 2 != 1) return; // finalized or serving
    for (int signum : {SIGINT}) // SIGTERM
    {
      uv_signal_t* signaler = new uv_signal_t;
      int r = uv_signal_init(&loop, signaler);
      if (r != 0)
      {
        delete signaler;
        continue;
      }
      signaler->data = this;
      r = uv_signal_start(signaler, on_signal_, signum);
      if (r != 0)
      {
        uv_close(reinterpret_cast<uv_handle_t*>(signaler)
          , [](uv_handle_t* handle) { delete reinterpret_cast<uv_signal_t*>(handle); }
        );
        continue;
      }
      // uv manage signalers in STL
      signalers.push_back(signaler);
    }
  }
  inline void designal_()
  {
    for (auto* signaler : signalers)
    {
      if (uv_is_closing(reinterpret_cast<uv_handle_t*>(signaler)) == 0) uv_close(reinterpret_cast<uv_handle_t*>(signaler)
        , [](uv_handle_t* handle) { delete reinterpret_cast<uv_signal_t*>(handle); }
      );
    }
    signalers.clear();
    uv_async_send(&loop_a); // sender acknoledge for last pending signaler events
  }
  inline void serve_() // loop in main thread
  {
    bool is_restart = false;
    uint8_t expected = 1;
    if (!state.compare_exchange_weak(expected, 2)) // initialized -> serving
    { // not initialized
      expected = 3; // stopped -> serving
      if (!state.compare_exchange_weak(expected, 2))
      { // not stopped
        if (state.load() != 2) return; // not serving
      }
      is_restart = true;
    }
    is_restart = is_restart || server_r.load();
    if (is_restart)
    {
      // 1. h2o dispose old context
      h2o_context_dispose(&ctx);
      uv_run(&loop, UV_RUN_ONCE); // process h2o context cleaning events
      // 2. h2o re-initialize context
      h2o_context_init(&ctx, &loop, &gconfig); // h2o load new uv listeners before serving
      // 3. h2o reset accept context
      hconfig_a[0] = hconfig;
      hconfig_a[1] = NULL;
      accept_ctx.hosts = hconfig_a;
      accept_ctx.ctx = &ctx;
      accept_ctx.ssl_ctx = ssl_ctx;
      // 4. uv update listeners h2o accept context records
      for (auto* listener : listeners)
      {
        listener->data = &accept_ctx; // uv load all h2o registry before serving
      }
    }
    server_r.store(false);
    start_time = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock_server(server_m);
      server_a.store(true);
      server_c.notify_all();
    }
    uv_run(&loop, UV_RUN_DEFAULT); // main loop blocking: connections -> uv -> h2o socket callback -> h2o handler -> business
    server_a.store(false);
    state.store(3); // stopped
  }
  inline void start_() // loop in worker thread
  {
    server_r.store(false);
    uint8_t expected = 1;
    if (!state.compare_exchange_weak(expected, 2)) // initialized -> serving
    { // not initialized
      expected = 3; // stopped -> serving
      if (!state.compare_exchange_weak(expected, 2)) return; // not stopped
      server_r.store(true);
    }
    server_a.store(false);
    server_t = std::thread([this]() { serve_(); });
    std::unique_lock<std::mutex> lock_server(server_m);
    server_c.wait(lock_server, [this]() { return server_a.load() || state.load() == 3; });
  }
  inline void stop_() // clear h2o http connections then uv tcp listeners/signalers
  {
    uint8_t expected = 2;
    if (!state.compare_exchange_strong(expected, 3)) return; // serving -> stopped
    delisten_();
    designal_();
    h2o_context_request_shutdown(&ctx); // h2o request shutdown active connections
    uv_async_send(&loop_a); // sender acknoledge
    uv_stop(&loop); // set flag for uv_run() to return; persistent sender/timer
    uv_async_send(&loop_a); // sender acknoledge for loop stop flag
    server_c.notify_all();
    if (server_t.joinable() && server_t.get_id() != std::this_thread::get_id()) server_t.join();
    server_a.store(false);
  }
  inline int64_t uptime_() const // ms
  {
    if (state.load() != 2) return 0; // not serving
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time).count();
  }
  inline void fina_()
  {
    const uint8_t s = state.load();
    if (s == 0) return; // already finalized
    if (s == 2) stop_(); // serving -> stopped
    // 1. uv stop acceptance
    delisten_();
    // 2. uv close signalers
    designal_();
    // 3. h2o request shutdown active connections
    h2o_context_request_shutdown(&ctx);
    uv_async_send(&loop_a); // sender acknoledge
    // 4. h2o dispose context
    h2o_context_dispose(&ctx); // context-owned
    uv_async_send(&loop_a); // sender acknoledge
    // 5. h2o dispose config
    h2o_config_dispose(&gconfig); // config-owned: h2o_handler_t* -> h2o_pathconf_t* -> h2o_hostconf_t* -> h2o_globalconf_t
    // 6. uv clear all remainings i.e. loop sender and timer
    uv_close(reinterpret_cast<uv_handle_t*>(&loop_a), NULL);
    uv_close(reinterpret_cast<uv_handle_t*>(&loop_t), NULL);
    uv_run(&loop, UV_RUN_DEFAULT); // no persistent sender/timer/listeners/signalers -> instant return
    // 7. uv close loop
    uv_loop_close(&loop);
    // 8. openssl dispose ssl context
    if (ssl_ctx)
    {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = NULL;
    }
    // 9. deregister all
    prefix_groups.clear();
    // 10. h2o advanced recycle memory management finalize
    h2o_buffer_clear_recycle(1); // clear all recycled buffer blocks
    h2o_mem_clear_recycle(&h2o_mem_pool_allocator, 1); // clear recycled memory pool chunks
    if (server_t.joinable() && server_t.get_id() != std::this_thread::get_id()) server_t.join();
    state.store(0); // finalized
    pthd.fina_();
  }
  inline void register_(std::string _prefix
    , const std::string& _method
    , http_f _business_
    , bool _async = true
    , uint64_t _timeout_ms = 0 // 0 = no timeout; >0 = timeout ms
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  )
  {
    if (state.load() % 2 != 1) return; // finalized or serving
    const http_m m(_method);
    // 1. prefix_c create if not exists
    auto& pc = prefix_groups[_prefix];
    // 2. h2o pathconf create if not exists
    if (!pc.pathconf) pc.pathconf = h2o_config_register_path(hconfig, _prefix.c_str(), 0);
    // 2.5. enable compression on this path if configured
    if (_compress)
    {
      h2o_compress_args_t compress_args;
      compress_args.min_size = _compress_min_size;
      compress_args.gzip.quality = _compress_gzip_quality;
      compress_args.brotli.quality = _compress_brotli_quality;
      h2o_compress_register(pc.pathconf, &compress_args);
    }
    // 3. check handler
    auto handler_it = pc.handlers.find(m);
    if (handler_it == pc.handlers.end())
    {
      // 4. h2o create handler allocating memory
      h2o_handler_t* raw_handler = h2o_create_handler(pc.pathconf, sizeof(http_h));
      // 5. placement new to construct http_h in the allocated memory
      http_h* handler = new(raw_handler) http_h();
      // 6. set h2o callback
      raw_handler->on_req = &http_h::on_req_;
      raw_handler->dispose = &http_h::dispose_;
      // 7. set fields in handler
      handler->method = _method;
      handler->business_ = std::move(_business_);
      handler->async = _async;
      handler->timeout_ms = _timeout_ms;
      handler->app = this;
      // 8. store handler in prefix_c
      pc.handlers[m] = handler;
    }
    else
    {
      // 9. update handler in prefix_c
      handler_it->second->method = _method;
      handler_it->second->business_ = std::move(_business_);
      handler_it->second->async = _async;
      handler_it->second->timeout_ms = _timeout_ms;
      handler_it->second->app = this;
    }
  }
  inline void get_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "GET", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void post_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "POST", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void put_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "PUT", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void delete_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "DELETE", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void patch_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "PATCH", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void options_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "OPTIONS", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void head_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "HEAD", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void trace_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "TRACE", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
  inline void connect_(std::string _prefix
    , http_f _business_
    , bool _async = true
    , bool _timeout_ms = 0
    , bool _compress = true
    , size_t _compress_min_size = 100
    , int _compress_gzip_quality = 1
    , int _compress_brotli_quality = 1
  ) { register_(_prefix, "CONNECT", std::move(_business_), _async, _timeout_ms, _compress, _compress_min_size, _compress_gzip_quality, _compress_brotli_quality); }
};

/* --------------------------------------------- */

struct http_r // response received
{
  int status;
  std::string reason;
  std::unordered_map<std::string, std::vector<std::string>> headers;
  std::string body;
  std::string vers;
  bool chunked_decoded; // chunk decode only once
  http_r() : status(0), chunked_decoded(false) {}
  http_r(const std::string& _raw_response) : status(0), chunked_decoded(false) { parse_(_raw_response); }
  inline void parse_(const std::string& _raw_response)
  {
    if (_raw_response.empty()) return;
    std::string_view raw_response(_raw_response);
    // 1. find header/body boundary
    size_t header_end = raw_response.find("\r\n\r\n");
    if (header_end == std::string_view::npos) return;
    std::string_view headers_section = raw_response.substr(0, header_end);
    std::string_view body_view = raw_response.substr(header_end + 4);
    body = std::string(body_view);
    // 2. parse status line
    size_t line_end = headers_section.find("\r\n");
    if (line_end == std::string_view::npos) line_end = headers_section.size();
    std::string_view status_line = headers_section.substr(0, line_end);
    size_t pos = line_end + 2;
    // 3. parse "HTTP/1.1 200 OK" with optional status text
    size_t first_space = status_line.find(' ');
    if (first_space == std::string_view::npos) return;
    vers = std::string(status_line.substr(0, first_space));
    size_t second_space = status_line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) // no status text
    {
      std::string_view code_view = status_line.substr(first_space + 1);
      try { status = std::stoi(std::string(code_view)); }
      catch (...) { return; }
    }
    else
    {
      std::string_view code_view = status_line.substr(first_space + 1, second_space - first_space - 1);
      try { status = std::stoi(std::string(code_view)); }
      catch (...) { return; }
      reason = std::string(status_line.substr(second_space + 1));
    }
    // 4. parse headers with folding support
    std::string current_key;
    std::string current_value;
    bool has_pending = false;
    auto flush_pending_ = [&]()
    {
      if (has_pending && !current_key.empty())
      {
        headers[current_key].push_back(current_value);
        current_value.clear();
        has_pending = false;
      }
    };
    while (pos < headers_section.size())
    {
      size_t line_start = pos;
      line_end = headers_section.find("\r\n", pos);
      if (line_end == std::string_view::npos) line_end = headers_section.size();
      std::string_view line = headers_section.substr(line_start, line_end - line_start);
      pos = line_end + 2;
      if (line.empty()) break; // RFC 7230: empty line ends headers
      if (line[0] == ' ' || line[0] == '\t') // header folding with continuation line
      {
        if (has_pending)
        {
          size_t start = line.find_first_not_of(" \t");
          if (start != std::string_view::npos) current_value += " " + std::string(line.substr(start));
        }
        // else skip orphaned continuation line
        continue;
      }
      // flush pending folded header at new header line
      flush_pending_();
      size_t colon = line.find(':');
      if (colon != std::string_view::npos)
      {
        std::string_view key = line.substr(0, colon);
        std::string_view value = line.substr(colon + 1);
        size_t start = value.find_first_not_of(' ');
        if (start != std::string_view::npos) value = value.substr(start);
        else value = "";
        std::string key_lower(key);
        std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(), ::tolower);
        current_key = key_lower;
        current_value = std::string(value);
        has_pending = true;
      }
      // else skip malformed header line without colon
    }
    flush_pending_(); // flush last pending header
    // 5. handle all body processing: chunked and content-encoding decompression
    process_body_();
  }
  inline void process_body_()
  {
    // 1. handle chunked transfer encoding first: precedence over Content-Length
    bool is_chunked = false;
    auto te_it = headers.find("transfer-encoding");
    if (te_it != headers.end() && !chunked_decoded)
    {
      // check all transfer-encoding values in order
      for (const auto& encoding : te_it->second)
      {
        if (encoding.find("chunked") != std::string::npos)
        {
          body = decode_chunk_(body);
          is_chunked = true;
          chunked_decoded = true;
          break;
        }
      }
    }
    // 2. validate and truncate by content-length
    if (!is_chunked)
    {
      auto cl_it = headers.find("content-length");
      if (cl_it != headers.end() && !cl_it->second.empty())
      {
        try
        {
          size_t expected_len = std::stoull(cl_it->second[0]);
          if (body.size() > expected_len) body = body.substr(0, expected_len);
        }
        catch (...) {}
      }
    }
    // 3. handle content-encoding decompression in reverse order
    auto ce_it = headers.find("content-encoding");
    if (ce_it != headers.end() && !ce_it->second.empty())
    {
      std::vector<std::string> encodings;
      for (const auto& header_val : ce_it->second)
      {
        size_t start = 0;
        while (start < header_val.size())
        {
          size_t comma = header_val.find(',', start);
          if (comma == std::string::npos) comma = header_val.size();
          std::string enc = header_val.substr(start, comma - start);
          size_t enc_start = enc.find_first_not_of(" \t");
          size_t enc_end = enc.find_last_not_of(" \t");
          if (enc_start != std::string::npos) encodings.push_back(enc.substr(enc_start, enc_end - enc_start + 1));
          start = comma + 1; // trim whitespace
        }
      }
      for (auto it = encodings.rbegin(); it != encodings.rend(); ++it) // LIFO decode
      {
        if (*it == "gzip") body = decode_gzip_(body);
        else if (*it == "deflate") body = decode_deflate_(body);
        else if (*it == "br") body = decode_brotli_(body);
      }
    }
  }
  static inline std::string decode_chunk_(const std::string& _chunked_body)
  {
    std::string decoded;
    size_t pos = 0;
    while (pos < _chunked_body.size())
    {
      // 1. find chunk size line
      size_t line_end = _chunked_body.find("\r\n", pos);
      if (line_end == std::string::npos) break;
      std::string size_line = _chunked_body.substr(pos, line_end - pos);
      // 2. handle chunk extensions "1a;name=value"
      size_t semicolon = size_line.find(';');
      if (semicolon != std::string::npos) size_line = size_line.substr(0, semicolon);
      // 3. trim whitespace
      size_t start = size_line.find_first_not_of(" \t");
      if (start == std::string::npos) break;
      size_t end = size_line.find_last_not_of(" \t");
      size_line = size_line.substr(start, end - start + 1);
      if (size_line.empty()) break;
      size_t chunk_size;
      try { chunk_size = std::stoull(size_line, nullptr, 16); }
      catch (...) { break; }
      pos = line_end + 2;
      if (chunk_size == 0)
      {
        // 4. last chunk: consume optional trailers until empty line
        while (pos < _chunked_body.size())
        {
          size_t trailer_end = _chunked_body.find("\r\n", pos);
          if (trailer_end == std::string::npos) break;
          if (trailer_end == pos) // empty line (end of trailers)
          {
            pos += 2;
            break;
          }
          pos = trailer_end + 2; // skip trailer line
        }
        break;
      }
      // 5. extract chunk data
      if (pos + chunk_size > _chunked_body.size()) break;
      decoded.append(_chunked_body.data() + pos, chunk_size);
      pos += chunk_size;
      // 6. skip trailing \r\n
      if (pos + 2 <= _chunked_body.size()
        && _chunked_body[pos] == '\r'
        && _chunked_body[pos + 1] == '\n'
      ) pos += 2;
      else break; // malformed chunk
    }
    return decoded;
  }
  static inline std::string decode_gzip_(const std::string& _compressed)
  {
    if (_compressed.empty()) return _compressed;
    z_stream stream = {};
    stream.next_in = (Bytef*)_compressed.data();
    stream.avail_in = _compressed.size();
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK)
    {
      fprintf(stderr, "http_r.decode_gzip_() [%d]: inflateInit2 failed\n", getpid());
      return _compressed;
    }
    std::string decompressed;
    decompressed.reserve(_compressed.size() * 3);
    char buffer[32768];
    int ret;
    do
    {
      stream.next_out = (Bytef*)buffer;
      stream.avail_out = sizeof(buffer);
      size_t before_out = stream.total_out;
      ret = inflate(&stream, Z_NO_FLUSH);
      size_t after_out = stream.total_out;
      if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
      {
        fprintf(stderr, "http_r.decode_gzip_() [%d]: inflate failed with code %d\n", getpid(), ret);
        inflateEnd(&stream);
        return _compressed;
      }
      if (ret == Z_BUF_ERROR && before_out == after_out)
      {
        fprintf(stderr, "http_r.decode_gzip_() [%d]: Z_BUF_ERROR with no progress\n", getpid());
        inflateEnd(&stream);
        return _compressed;
      }
      size_t have = sizeof(buffer) - stream.avail_out;
      decompressed.append(buffer, have);
    } while (ret != Z_STREAM_END);
    inflateEnd(&stream);
    return decompressed;
  }
  static inline std::string decode_deflate_(const std::string& _compressed)
  {
    if (_compressed.empty()) return _compressed;
    z_stream stream = {};
    stream.next_in = (Bytef*)_compressed.data();
    stream.avail_in = _compressed.size();
    int ret = inflateInit2(&stream, -MAX_WBITS);
    if (ret != Z_OK)
    {
      stream = {}; // reset stream
      stream.next_in = (Bytef*)_compressed.data();
      stream.avail_in = _compressed.size();
      ret = inflateInit(&stream);
      if (ret != Z_OK)
      {
        fprintf(stderr, "http_r.decode_deflate_() [%d]: inflateInit failed\n", getpid());
        return _compressed;
      }
    }
    std::string decompressed;
    decompressed.reserve(_compressed.size() * 3);
    char buffer[32768];
    do
    {
      stream.next_out = (Bytef*)buffer;
      stream.avail_out = sizeof(buffer);
      size_t before_out = stream.total_out;
      ret = inflate(&stream, Z_NO_FLUSH);
      size_t after_out = stream.total_out;
      if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
      {
        fprintf(stderr, "http_r.decode_deflate_() [%d]: inflate failed with code %d\n", getpid(), ret);
        inflateEnd(&stream);
        return _compressed;
      }
      // break if Z_BUF_ERROR with no progress
      if (ret == Z_BUF_ERROR && before_out == after_out) break;
      size_t have = sizeof(buffer) - stream.avail_out;
      decompressed.append(buffer, have);
    } while (ret != Z_STREAM_END);
    inflateEnd(&stream);
    return decompressed;
  }
  static inline std::string decode_brotli_(const std::string& _compressed)
  {
    if (_compressed.empty()) return _compressed;
    size_t available_in = _compressed.size();
    const uint8_t* next_in = (const uint8_t*)_compressed.data();
    BrotliDecoderState* state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (!state)
    {
      fprintf(stderr, "http_r.decode_brotli_() [%d]: BrotliDecoderCreateInstance failed\n", getpid());
      return _compressed;
    }
    std::string decompressed;
    decompressed.reserve(_compressed.size() * 3);
    uint8_t buffer[32768];
    BrotliDecoderResult result;
    bool stream_finished = false;
    while (!stream_finished)
    {
      size_t available_out = sizeof(buffer);
      uint8_t* next_out = buffer;
      result = BrotliDecoderDecompressStream(state
        , &available_in
        , &next_in
        , &available_out
        , &next_out
        , NULL
      );
      size_t have = sizeof(buffer) - available_out;
      if (have > 0) decompressed.append((char*)buffer, have); // extract any output produced
      if (result == BROTLI_DECODER_RESULT_SUCCESS) stream_finished = true;
      else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue;
      else if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT)
      {
        if (available_in == 0)
        {
          fprintf(stderr, "http_r.decode_brotli_() [%d]: truncated/incomplete brotli stream\n", getpid());
          BrotliDecoderDestroyInstance(state);
          return _compressed;
        }
        continue;
      }
      else if (result == BROTLI_DECODER_RESULT_ERROR)
      {
        auto error = BrotliDecoderGetErrorCode(state);
        fprintf(stderr, "http_r.decode_brotli_() [%d]: decompression failed with error %d\n", getpid(), error);
        BrotliDecoderDestroyInstance(state);
        return _compressed;
      }
      else // unexpected result state
      {
        fprintf(stderr, "http_r.decode_brotli_() [%d]: unexpected decoder result %d\n", getpid(), result);
        BrotliDecoderDestroyInstance(state);
        return _compressed;
      }
    }
    BrotliDecoderDestroyInstance(state);
    return decompressed;
  }
  inline bool is_ok_() const { return status >= 200 && status < 300; }
  inline std::vector<std::string> header_(const std::string& _key) const
  {
    auto it = headers.find(_key);
    return it != headers.end() ? it->second : std::vector<std::string>();
  }
  inline bool header_has_(const std::string& _key) const
  {
    return headers.find(_key) != headers.end();
  }
  inline bool header_has_(const std::string& _key, const std::string& _value) const
  {
    auto it = headers.find(_key);
    if (it == headers.end()) return false;
    return std::find(it->second.begin(), it->second.end(), _value) != it->second.end();
  }
  inline bool header_has_(const std::pair<std::string, std::string>& _header) const
  {
    return header_has_(_header.first, _header.second);
  }
};

class http_t // utilities
{
public:
  static inline bool socket_set_block_(int sock, bool blocking)
  {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    if (blocking) flags &= ~O_NONBLOCK;
    else flags |= O_NONBLOCK;
    return fcntl(sock, F_SETFL, flags) != -1;
  }
  static inline void socket_set_timeout_(int sock, int timeout_ms)
  {
    if (timeout_ms <= 0) return;
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }
  static inline bool socket_wait_(int sock, bool for_write, int timeout_ms)
  {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int ret = select(sock + 1, for_write ? NULL : &fds, for_write ? &fds : NULL, NULL, &tv);
    return ret == 1;
  }
  static inline int socket_connect_(int sock, const sockaddr_in& addr, int timeout_ms)
  { // 0 = success; 1 = timeout; 2 = error
    if (timeout_ms <= 0)
    {
      int ret = connect(sock, (sockaddr*)&addr, sizeof(addr));
      return ret == 0 ? 0 : 2;
    }
    if (!socket_set_block_(sock, false)) return 2;
    int ret = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (ret == 0) { socket_set_block_(sock, true); return 0; }
    if (errno != EINPROGRESS) return 2;
    if (!socket_wait_(sock, true, timeout_ms)) return 1;
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) return 2;
    socket_set_block_(sock, true);
    return 0;
  }
  static inline bool socket_connect_is_(int sock, const sockaddr_in& addr, int timeout_ms)
  {
    return socket_connect_(sock, addr, timeout_ms) == 0;
  }
  static inline void ssl_init_()
  {
    static bool initialized = false;
    if (!initialized)
    {
      SSL_library_init();
      SSL_load_error_strings();
      OpenSSL_add_all_algorithms();
      initialized = true;
    }
  }
  static inline void ssl_clean_(SSL*& ssl, SSL_CTX*& ssl_ctx, int sock)
  {
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); ssl = NULL; }
    if (ssl_ctx) { SSL_CTX_free(ssl_ctx); ssl_ctx = NULL; }
    if (sock >= 0) close(sock);
  }
  static inline bool ssl_handshake_(SSL* ssl, int sock, int timeout_ms)
  {
    if (!socket_set_block_(sock, false)) return false;
    int default_timeout = timeout_ms > 0 ? timeout_ms : 20000;
    int ssl_ret;
    while ((ssl_ret = SSL_connect(ssl)) != 1)
    {
      int ssl_error = SSL_get_error(ssl, ssl_ret);
      if (ssl_error == SSL_ERROR_WANT_READ)
      {
        if (!socket_wait_(sock, false, default_timeout)) return false;
      }
      else if (ssl_error == SSL_ERROR_WANT_WRITE)
      {
        if (!socket_wait_(sock, true, default_timeout)) return false;
      }
      else
      {
        fprintf(stderr, "http_t.ssl_handshake_() [%d]: SSL connection failed with error: %d\n", getpid(), ssl_error);
        return false;
      }
    }
    return socket_set_block_(sock, true);
  }
  static inline bool all_send_(SSL* ssl, int sock, const std::string& data, int timeout_ms)
  {
    size_t total = 0;
    int default_timeout = timeout_ms > 0 ? timeout_ms : 30000;
    while (total < data.size())
    {
      ssize_t sent;
      if (ssl)
      {
        if (!socket_set_block_(sock, false)) return false;
        sent = SSL_write(ssl, data.data() + total, data.size() - total);
        if (sent > 0) { total += sent; continue; }
        int ssl_error = SSL_get_error(ssl, sent);
        if (ssl_error == SSL_ERROR_WANT_READ)
        {
          if (!socket_wait_(sock, false, default_timeout)) return false;
          continue;
        }
        else if (ssl_error == SSL_ERROR_WANT_WRITE)
        {
          if (!socket_wait_(sock, true, default_timeout)) return false;
          continue;
        }
        else
        {
          fprintf(stderr, "http_t.all_send_() [%d]: SSL send failed with error: %d\n", getpid(), ssl_error);
          return false;
        }
      }
      else
      {
        sent = send(sock, data.data() + total, data.size() - total, 0);
        if (sent < 0)
        {
          if (errno == EINTR) continue;
          fprintf(stderr, "http_t.all_send_() [%d]: Send failed\n", getpid());
          return false;
        }
        total += sent;
      }
    }
    if (ssl) socket_set_block_(sock, true);
    return true;
  }
  static inline std::string all_recv_(SSL *ssl, int sock, int timeout_ms)
  {
    std::string response;
    char buf[MAX2_(4096, sysconf(_SC_PAGESIZE))];
    int default_timeout = timeout_ms > 0 ? timeout_ms : 20000;
    bool headers_complete = false;
    size_t headers_end_pos = 0;
    bool is_chunked = false;
    size_t content_length = 0;
    bool has_content_length = false;
    while (true)
    {
      ssize_t r;
      if (ssl)
      {
        if (!socket_wait_(sock, false, default_timeout)) break;
        r = SSL_read(ssl, buf, sizeof(buf));
        if (r <= 0)
        {
          int ssl_error = SSL_get_error(ssl, r);
          if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) continue;
          break;
        }
      }
      else
      {
        r = recv(sock, buf, sizeof(buf), 0);
        if (r < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
        if (r == 0) break; // connection closed
      }
      response.append(buf, r);
      // parse headers first time
      if (!headers_complete)
      {
        size_t header_end = response.find("\r\n\r\n");
        if (header_end != std::string::npos)
        {
          headers_complete = true;
          headers_end_pos = header_end + 4;
          std::string headers_lower = response.substr(0, header_end);
          std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(), ::tolower);
          if (headers_lower.find("transfer-encoding: chunked") != std::string::npos) is_chunked = true;
          size_t cl_pos = headers_lower.find("content-length:");
          if (cl_pos != std::string::npos)
          {
            size_t value_start = cl_pos + 15; // length of "content-length:"
            while (value_start < header_end
              && (response[value_start] == ' ' || response[value_start] == '\t')
            ) value_start++;
            size_t value_end = response.find("\r\n", value_start);
            if (value_end != std::string::npos && value_end <= header_end)
            {
              try
              {
                content_length = std::stoull(response.substr(value_start, value_end - value_start));
                has_content_length = true;
              } catch (...) {}
            }
          }
        }
      }
      if (headers_complete)
      {
        if (is_chunked)
        {
          if (response.size() >= headers_end_pos + 5)
          {
            size_t search_start = headers_end_pos;
            size_t pos = response.find("0\r\n\r\n", search_start); // end of chunked encoding
            if (pos != std::string::npos) break;
          }
        }
        else if (has_content_length)
        {
          if (response.size() >= headers_end_pos + content_length) break;
        }
        // if neither chunked nor content-length rely on connection close
      }
    }
    return response;
  }
  static inline short ping_(const std::string& _host
    , uint16_t _port
    , int _timeout_ms = 3000
  ) // 0 = success; 1 = timeout; 2 = connection refused; -1 = socket error; -2 = invalid host; -3 = fcntl error
  {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
      fprintf(stderr, "http_t.ping_() [%d]: Failed to create socket\n", getpid());
      return -1;
    }
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_port);
    if (inet_pton(AF_INET, _host.c_str(), &addr.sin_addr) <= 0)
    {
      fprintf(stderr, "http_t.ping_() [%d]: Invalid host format %s\n", getpid(), _host.c_str());
      close(sock);
      return -2;
    }
    int status = socket_connect_(sock, addr, _timeout_ms);
    close(sock);
    if (status == 0) return 0;
    if (status == 1) return 1;
    return 2;
  }
  template <typename MapType = std::unordered_map<std::string, std::string>>
  static inline std::string request_(const std::string& _host
    , uint16_t _port
    , const std::string& _method
    , const std::string& _path
    , const std::string& _body = ""
    , const MapType& _headers = {}
    , int _timeout_ms = 0
    , bool _use_ssl = false
    , bool _self_ssl = true
    , const std::string& _vers = "HTTP/1.1"
  )
  {
    SSL_CTX* ssl_ctx = NULL;
    SSL* ssl = NULL;
    int sock = -1;
    if (_use_ssl)
    {
      ssl_init_();
      ssl_ctx = SSL_CTX_new(TLS_client_method());
      if (!ssl_ctx)
      {
        fprintf(stderr, "http_t.request_() [%d]: Failed to create SSL context\n", getpid());
        return "";
      }
      if (_self_ssl) SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); // no verification: accepts self-signed certs
      else
      {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1)
        {
          fprintf(stderr, "http_t.request_() [%d]: Failed to load CA bundle\n", getpid());
          ssl_clean_(ssl, ssl_ctx, -1);
          return "";
        }
      }
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
      fprintf(stderr, "http_t.request_() [%d]: Failed to create socket\n", getpid());
      ssl_clean_(ssl, ssl_ctx, -1);
      return "";
    }
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_port);
    if (inet_pton(AF_INET, _host.c_str(), &addr.sin_addr) <= 0)
    {
      fprintf(stderr, "http_t.request_() [%d]: Invalid host format %s\n", getpid(), _host.c_str());
      ssl_clean_(ssl, ssl_ctx, sock);
      return "";
    }
    if (!socket_connect_is_(sock, addr, _timeout_ms))
    {
      fprintf(stderr, "http_t.request_() [%d]: Failed to connect to %s:%d\n", getpid(), _host.c_str(), _port);
      ssl_clean_(ssl, ssl_ctx, sock);
      return "";
    }
    socket_set_timeout_(sock, _timeout_ms);
    if (_use_ssl)
    {
      ssl = SSL_new(ssl_ctx);
      if (!ssl)
      {
        fprintf(stderr, "http_t.request_() [%d]: Failed to create SSL connection\n", getpid());
        ssl_clean_(ssl, ssl_ctx, sock);
        return "";
      }
      SSL_set_fd(ssl, sock);
      if (!ssl_handshake_(ssl, sock, _timeout_ms))
      {
        fprintf(stderr, "http_t.request_() [%d]: SSL handshake failed\n", getpid());
        ssl_clean_(ssl, ssl_ctx, sock);
        return "";
      }
    }
    std::ostringstream req;
    req << _method << " " << _path << " " << _vers << "\r\n";
    req << "Host: " << _host << ":" << _port << "\r\n";
    using ValueType = std::decay_t<decltype(*std::begin(std::declval<MapType>()))>;
    if constexpr (std::is_convertible_v<ValueType, std::pair<std::string, std::vector<std::string>>>)
    { // multi-value headers: <string, vector<string>>
      for (const auto& [key, values] : _headers)
      {
        for (const auto& value : values)
        {
          req << key << ": " << value << "\r\n";
        }
      }
    }
    else if constexpr (std::is_convertible_v<ValueType, std::pair<std::string, std::string>>)
    { // single-value headers: <string, string>
      for (const auto& [key, value] : _headers)
      {
        req << key << ": " << value << "\r\n";
      }
    }
    if (!_body.empty()) req << "Content-Length: " << _body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << _body;
    std::string req_str = req.str();
    if (!all_send_(ssl, sock, req_str, _timeout_ms))
    {
      fprintf(stderr, "http_t.request_() [%d]: Failed to send request\n", getpid());
      ssl_clean_(ssl, ssl_ctx, sock);
      return "";
    }
    std::string response = all_recv_(ssl, sock, _timeout_ms);
    ssl_clean_(ssl, ssl_ctx, sock);
    return response;
  }
  static inline bool response_is_(const std::string& _response
    , int _expected_status
    , const std::string& _expected_body = ""
  )
  {
    http_r parsed(_response);
    if (parsed.status != _expected_status) return false;
    if (_expected_body.empty()) return true;
    return parsed.body == _expected_body;
  }
  static inline bool response_json_is_(const std::string& _response
    , int _expected_status
    , const nlohmann::json& _expected_json
  )
  {
    http_r parsed(_response);
    if (parsed.status != _expected_status) return false;
    try { return nlohmann::json::parse(parsed.body) == _expected_json; }
    catch (...) { return false; }
  }
  static inline nlohmann::json response_json_(const std::string& _response)
  {
    http_r parsed(_response);
    if (parsed.status == 0) return nlohmann::json(); // parsing failed
    try
    {
      return nlohmann::json::parse(parsed.body);
    }
    catch (...) { return nlohmann::json(); }
  }
};