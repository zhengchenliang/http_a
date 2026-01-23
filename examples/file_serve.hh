#pragma once

#include "../include/http_a_server.hh"

// mime type map
inline std::unordered_map<std::string, std::string> mime_types =
{
  // text
  {".html", "text/html; charset=utf-8"},
  {".htm", "text/html; charset=utf-8"},
  {".css", "text/css; charset=utf-8"},
  {".js", "application/javascript; charset=utf-8"},
  {".mjs", "application/javascript; charset=utf-8"},
  {".json", "application/json; charset=utf-8"},
  {".xml", "application/xml; charset=utf-8"},
  {".txt", "text/plain; charset=utf-8"},
  {".md", "text/markdown; charset=utf-8"},
  {".csv", "text/csv; charset=utf-8"},

  // images
  {".png", "image/png"},
  {".jpg", "image/jpeg"},
  {".jpeg", "image/jpeg"},
  {".gif", "image/gif"},
  {".svg", "image/svg+xml"},
  {".webp", "image/webp"},
  {".ico", "image/x-icon"},
  {".bmp", "image/bmp"},
  {".tiff", "image/tiff"},
  {".tif", "image/tiff"},

  // fonts
  {".woff", "font/woff"},
  {".woff2", "font/woff2"},
  {".ttf", "font/ttf"},
  {".otf", "font/otf"},
  {".eot", "application/vnd.ms-fontobject"},

  // video
  {".mp4", "video/mp4"},
  {".webm", "video/webm"},
  {".ogg", "video/ogg"},
  {".avi", "video/x-msvideo"},
  {".mov", "video/quicktime"},

  // audio
  {".mp3", "audio/mpeg"},
  {".wav", "audio/wav"},
  {".m4a", "audio/mp4"},
  {".flac", "audio/flac"},

  // documents
  {".pdf", "application/pdf"},
  {".zip", "application/zip"},
  {".tar", "application/x-tar"},
  {".gz", "application/gzip"},
  {".7z", "application/x-7z-compressed"},
  {".rar", "application/vnd.rar"},

  // web assembly
  {".wasm", "application/wasm"},

  // manifests
  {".manifest", "text/cache-manifest"},
  {".webmanifest", "application/manifest+json"},
};

inline std::string get_mime_(const std::string& _path)
{
  auto dot = _path.rfind('.');
  if (dot == std::string::npos) return std::string("application/octet-stream");

  std::string ext = _path.substr(dot);
  // convert to lowercase for case-insensitive matching
  std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

  auto it = mime_types.find(ext);
  return (it != mime_types.end()) ? it->second : std::string("application/octet-stream");
}

inline std::string etag_generate_(time_t _mtime, off_t _size)
{
  // simple etag: "mtime-size" in hex
  std::ostringstream oss;
  oss << "\"" << std::hex << _mtime << "-" << std::hex << _size << "\"";
  return oss.str();
}

inline std::string format_http_time_(time_t _time)
{
  // format as RFC 7231 (HTTP-date)
  struct tm tm;
  gmtime_r(&_time, &tm);
  char buf[64];
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  return std::string(buf);
}

inline void log_request_(const http_q& _q, int _status, const std::string& _path, size_t _bytes)
{
  auto now = std::chrono::system_clock::now();
  auto time_c = std::chrono::system_clock::to_time_t(now);

  char time_buf[32];
  struct tm tm_info;
  localtime_r(&time_c, &tm_info);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

  std::cout << "[" << time_buf << "] "
            << _status << " "
            << _q.url_prefix_() << _q.url_rest_() << " "
            << "(" << _bytes << " bytes) "
            << "-> " << _path
            << std::endl;
}