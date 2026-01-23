/**
 * hello_world.cc — Minimal HTTP server example
 *
 * Demonstrates basic http_a usage:
 *   - Single endpoint registration
 *   - Sync and async handlers
 *   - Graceful shutdown via signal
 *
 * Build: cmake --build . --target hello_world
 * Run:   ./hello_world [port]
 * Test:  curl http://localhost:8080/
 */

#include "../include/http_a_server.hh"

int main(int argc, char** argv)
{
  int port = (argc > 1) ? std::atoi(argv[1]) : 8080;

  http_a app;

  // GET / — sync handler (simple, blocks event loop)
  app.get_("/", [](const http_q& _q, http_s& _s)
  {
    _s.status_(200);
    _s.send_text_("Hello, World!\n");
  }, false); // sync

  // GET /async — async handler (non-blocking, uses thread pool)
  app.get_("/async", [](const http_q& _q, http_s& _s)
  {
    // simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    _s.status_(200);
    _s.header_json_();
    _s.send_(R"({"message": "Hello from async handler!"})");
  }, true); // async

  // GET /info — request info
  app.get_("/info", [](const http_q& _q, http_s& _s)
  {
    nlohmann::json info;
    info["path"] = _q.url_();
    info["version"] = _q.http_vers_();
    info["headers"] = _q.headers_();
    info["queries"] = _q.queries_();
    _s.status_(200);
    _s.send_json_(info);
  }, true);

  // setup and run
  app.listen_("0.0.0.0", port);
  app.signal_(); // graceful shutdown on SIGINT

  std::cout << "http_a server listening on http://0.0.0.0:" << port << std::endl;
  std::cout << "Endpoints:" << std::endl;
  std::cout << "  GET /       — Hello World (sync)" << std::endl;
  std::cout << "  GET /async  — Hello World (async)" << std::endl;
  std::cout << "  GET /info   — Request info" << std::endl;
  std::cout << "Press Ctrl+C to stop." << std::endl;

  app.serve_(); // blocks until signal

  std::cout << "Server stopped." << std::endl;
  return 0;
}

