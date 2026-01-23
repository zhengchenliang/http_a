#include "../include/http_a_server.hh"

#include <cassert>
#include <fstream>
#include <sstream>
#include <cstring>

int main(int argc, char** argv)
{

std::cout << "=== Structure Size Analysis ===" << std::endl;
std::cout << "sizeof(h2o_socket_t) = " << sizeof(h2o_socket_t) << " bytes" << std::endl;
std::cout << "sizeof(uv_tcp_t) = " << sizeof(uv_tcp_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_buffer_t) = " << sizeof(h2o_buffer_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_conn_t) = " << sizeof(h2o_conn_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_req_t) = " << sizeof(h2o_req_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_timer_t) = " << sizeof(h2o_timer_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_iovec_t) = " << sizeof(h2o_iovec_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_headers_t) = " << sizeof(h2o_headers_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_res_t) = " << sizeof(h2o_res_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_mem_pool_t) = " << sizeof(h2o_mem_pool_t) << " bytes" << std::endl;
// Calculate h2o_multithread_queue_t size manually
// Structure: uv_async_t + pthread_mutex_t + { h2o_linklist_t active, h2o_linklist_t inactive }
std::cout << "sizeof(uv_async_t) = " << sizeof(uv_async_t) << " bytes" << std::endl;
std::cout << "sizeof(pthread_mutex_t) = " << sizeof(pthread_mutex_t) << " bytes" << std::endl;
std::cout << "sizeof(h2o_linklist_t) = " << sizeof(h2o_linklist_t) << " bytes" << std::endl;
size_t queue_size = sizeof(uv_async_t) + sizeof(pthread_mutex_t) + 2 * sizeof(h2o_linklist_t);
std::cout << "sizeof(h2o_multithread_queue_t) ≈ " << queue_size << " bytes" << std::endl;

// Buffer allocation details
std::cout << "\n=== Buffer Allocation Details ===" << std::endl;
std::cout << "H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE = " << H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE << " bytes" << std::endl;
size_t buffer_header_size = offsetof(h2o_buffer_t, _buf);
std::cout << "h2o_buffer_t header size (offsetof _buf) = " << buffer_header_size << " bytes" << std::endl;
size_t min_buffer_alloc = (1 << 12); // H2O_BUFFER_MIN_ALLOC_POWER = 12
std::cout << "Minimum buffer allocation (2^12) = " << min_buffer_alloc << " bytes" << std::endl;
std::cout << "Total minimum buffer allocation (header + data) = " << (buffer_header_size + min_buffer_alloc) << " bytes" << std::endl;

std::cout << "===========================================================\n" << std::endl;

std::cout << "=== Test 1: Basic State Management ===" << std::endl;
{
  http_a app;
  assert(app.state.load() == 1); // initialized
  std::cout << "✓ State is initialized after construction" << std::endl;
}
std::cout << "✓ Destructor properly finalizes" << std::endl;

std::cout << "\n=== Test 2: Listen Setup ===" << std::endl;
{
  http_a app;
  assert(app.state.load() == 1);

  try
  {
    app.listen_("127.0.0.1", 18080);
    assert(app.listeners.size() == 1);
    std::cout << "✓ listen_() successfully created listener" << std::endl;
  }
  catch (const std::exception& e)
  {
    std::cerr << "✗ listen_() failed: " << e.what() << std::endl;
    return 1;
  }
}

std::cout << "\n=== Test 3: Route Registration ===" << std::endl;
{
  http_a app;

  app.get_("/test", [](const http_q& q, http_s& s) {
    // Empty handler - just testing registration
  }, false); // sync mode

  assert(app.prefix_groups.find("/test") != app.prefix_groups.end());
  std::cout << "✓ Route registered successfully" << std::endl;

  // Test updating route
  app.get_("/test", [](const http_q& q, http_s& s) {
    // Updated handler
  }, false); // sync mode

  assert(app.prefix_groups.find("/test") != app.prefix_groups.end());
  std::cout << "✓ Route update works" << std::endl;
}

std::cout << "\n=== Test 4: Multiple HTTP Methods ===" << std::endl;
{
  http_a app;

  app.get_("/get", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.post_("/post", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.put_("/put", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.delete_("/delete", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.patch_("/patch", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.options_("/options", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.head_("/head", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.trace_("/trace", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.connect_("/connect", [](const http_q& q, http_s& s) {}, false); // sync mode

  assert(app.prefix_groups.size() == 9);
  std::cout << "✓ Multiple HTTP methods registered" << std::endl;
}

std::cout << "\n=== Test 5: Server Lifecycle (serve/stop) ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18081);

  app.get_("/hello", [](const http_q& q, http_s& s) {
    s.status_(200);
    s.send_text_("OK");
  }, false); // sync mode

  // Start server in thread
  std::thread server_thread([&app]() {
    app.serve_();
  });

  // Wait for server to start
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  assert(app.state.load() == 2); // serving
  std::cout << "✓ Server started (state = serving)" << std::endl;

  // Stop server
  app.stop_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  assert(app.state.load() == 3); // stopped
  std::cout << "✓ Server stopped (state = stopped)" << std::endl;

  server_thread.join();
}

std::cout << "\n=== Test 6: Multiple serve/stop Cycles ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18082);

  app.get_("/cycle", [](const http_q& q, http_s& s) {}, false); // sync mode

  // First cycle
  std::thread t1([&app]() {
    app.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 2);
  app.stop_();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 3);
  t1.join();
  std::cout << "✓ First serve/stop cycle completed" << std::endl;

  // Second cycle
  std::thread t2([&app]() {
    app.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 2);
  app.stop_();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 3);
  t2.join();
  std::cout << "✓ Second serve/stop cycle completed" << std::endl;

  // Third cycle
  std::thread t3([&app]() {
    app.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 2);
  app.stop_();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 3);
  t3.join();
  std::cout << "✓ Third serve/stop cycle completed" << std::endl;
}

std::cout << "\n=== Test 7: State Transitions Protection ===" << std::endl;
{
  // Can't listen when finalized
  http_a app2;
  app2.state.store(0); // finalized (in fact illegal way to set state)
  app2.listen_("127.0.0.1", 18084);
  assert(app2.listeners.size() == 0); // Should not add listener
  std::cout << "✓ listen_() blocked when finalized" << std::endl;
  app2.state.store(1); // initialized

  // Can't listen when serving
  http_a app3;
  app3.listen_("127.0.0.1", 18085);
  std::thread t_serving([&app3]() {
    app3.serve_(); // start serving in thread
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(30)); // make sure we're serving
  assert(app3.state.load() == 2); // serving
  size_t before = app3.listeners.size();
  app3.listen_("127.0.0.1", 18086);
  assert(app3.listeners.size() == before); // Should not add listener
  std::cout << "✓ listen_() blocked when serving" << std::endl;
  app3.stop_();
  t_serving.join();
}

std::cout << "\n=== Test 8: SSL Setup (without actual cert) ===" << std::endl;
{
  http_a app;

  // Try to setup SSL with non-existent cert (should throw)
  try
  {
    app.ssl_("/nonexistent/cert.pem", "/nonexistent/key.pem");
    std::cerr << "✗ SSL setup should have thrown exception" << std::endl;
    return 1;
  }
  catch (const std::exception& e)
  {
    std::cout << "✓ SSL setup correctly throws on invalid cert" << std::endl;
  }

  // SSL setup should not affect state when finalized
  http_a app2;
  app2.state.store(0); // finalized
  app2.ssl_("/nonexistent/cert.pem", "/nonexistent/key.pem");
  assert(app2.ssl_ctx == NULL); // Should not set ssl_ctx
  std::cout << "✓ ssl_() blocked when finalized" << std::endl;
  app2.state.store(1); // initialized

  // SSL setup should not affect state when serving
  http_a app3;
  app3.listen_("127.0.0.1", 18087);
  std::thread t_serving2([&app3]() {
    app3.serve_(); // start serving in thread
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(30)); // ensure serving
  app3.ssl_("/nonexistent/cert.pem", "/nonexistent/key.pem");
  assert(app3.ssl_ctx == NULL); // Should not set ssl_ctx
  std::cout << "✓ ssl_() blocked when serving" << std::endl;
  app3.stop_();
  t_serving2.join();
}

std::cout << "\n=== Test 9: Signal Handler Setup ===" << std::endl;
{
  http_a app;
  app.signal_();
  assert(app.signalers.size() == 1); // SIGINT
  std::cout << "✓ Signal handlers registered" << std::endl;

  // Signal setup should not work when finalized
  http_a app2;
  app2.state.store(0); // finalized
  app2.signal_();
  assert(app2.signalers.size() == 0);
  std::cout << "✓ signal_() blocked when finalized" << std::endl;
  app2.state.store(1); // initialized

  // Signal setup should not work when serving
  http_a app3;
  app3.listen_("127.0.0.1", 18088);
  std::thread t_serving3([&app3]() {
    app3.serve_(); // start serving in thread
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(30)); // ensure serving
  assert(app3.state.load() == 2); // serving
  app3.signal_();
  assert(app3.signalers.size() == 0);
  std::cout << "✓ signal_() blocked when serving" << std::endl;
  app3.listen_("0.0.0.0", 18089);
  assert(app3.listeners.size() == 1);
  std::cout << "✓ listen_() blocked at serving" << std::endl;
  app3.stop_();
  t_serving3.join();

  app3.signal_();
  assert(app3.signalers.size() == 1);
  std::cout << "✓ signal_() worked at stopped" << std::endl;
  app3.listen_("0.0.0.0", 18090);
  assert(app3.listeners.size() == 1);
  std::cout << "✓ listen_() worked at stopped" << std::endl;
  app3.listen_("0.0.0.0", 18091);
  assert(app3.listeners.size() == 2);
  std::cout << "✓ listen_() worked at stopped" << std::endl;
  std::thread t_serving4([&app3]() {
    app3.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app3.state.load() == 2);
  std::cout << "✓ serve_() worked at stopped" << std::endl;
  assert(app3.listeners.size() == 2);
  app3.stop_();
  assert(app3.state.load() == 3);
  std::cout << "✓ stop_() worked at serving" << std::endl;
  t_serving4.join();
}

std::cout << "\n=== Test 10: Multiple Listeners ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18089);
  app.listen_("127.0.0.1", 18090);
  assert(app.listeners.size() == 2);
  std::cout << "✓ Multiple listeners supported" << std::endl;
}

std::cout << "\n=== Test 11: Route Prefix Matching ===" << std::endl;
{
  http_a app;

  app.get_("/api", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.get_("/api/v1", [](const http_q& q, http_s& s) {}, false); // sync mode
  app.get_("/api/v1/users", [](const http_q& q, http_s& s) {}, false); // sync mode

  assert(app.prefix_groups.size() == 3);
  assert(app.prefix_groups.find("/api") != app.prefix_groups.end());
  assert(app.prefix_groups.find("/api/v1") != app.prefix_groups.end());
  assert(app.prefix_groups.find("/api/v1/users") != app.prefix_groups.end());
  std::cout << "✓ Multiple prefix routes registered" << std::endl;
}

std::cout << "\n=== Test 12: Idempotent stop_() ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18091);

  std::thread server_thread([&app]() {
    app.serve_();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 2);

  // Call stop multiple times
  app.stop_();
  app.stop_();
  app.stop_();

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 3);
  std::cout << "✓ Multiple stop_() calls are safe (idempotent)" << std::endl;

  server_thread.join();
}

std::cout << "\n=== Test 13: Idempotent fina_() ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18092);

  // Call fina multiple times
  app.fina_();
  app.fina_();
  app.fina_();

  assert(app.state.load() == 0);
  std::cout << "✓ Multiple fina_() calls are safe (idempotent)" << std::endl;
}

std::cout << "\n=== Test 14: serve_() State Protection ===" << std::endl;
{
  http_a app;

  // Can't serve when finalized
  app.state.store(0); // finalized
  app.serve_();
  assert(app.state.load() == 0); // Should remain finalized
  std::cout << "✓ serve_() blocked when finalized" << std::endl;
  app.state.store(1); // initialized

  // Can serve when initialized
  http_a app2;
  app2.listen_("127.0.0.1", 18093);
  std::thread t([&app2]() {
    app2.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app2.state.load() == 2); // Should be serving
  app2.stop_();
  t.join();
  std::cout << "✓ serve_() works when initialized" << std::endl;

  // Can restart serve when stopped
  http_a app3;
  app3.listen_("127.0.0.1", 18094);
  std::thread t1([&app3]() {
    app3.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  app3.stop_();
  t1.join();
  assert(app3.state.load() == 3); // stopped

  std::thread t2([&app3]() {
    app3.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app3.state.load() == 2); // Should be serving again
  app3.stop_();
  t2.join();
  std::cout << "✓ serve_() can restart from stopped state" << std::endl;
}

std::cout << "\n=== Test 15: Context Reset on Restart ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18095);
  app.get_("/test", [](const http_q& q, http_s& s) {}, false); // sync mode

  // First serve
  std::thread t1([&app]() {
    app.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  app.stop_();
  t1.join();

  // Second serve (should reset context)
  std::thread t2([&app]() {
    app.serve_();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  assert(app.state.load() == 2);
  app.stop_();
  t2.join();

  std::cout << "✓ Context properly reset on restart" << std::endl;
}

std::cout << "\n=== Test 16: URL Fields and Basic Response ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18096);

  // Test URL field extraction and response
  bool handler_called = false;
  std::string captured_url, captured_url_normal, captured_url_prefix, captured_url_rest, captured_url_query;
  std::string captured_query_token, captured_query_name;
  std::string captured_rest_raw;
  std::unordered_map<std::string, std::string> captured_queries;
  std::unordered_map<std::string, std::string> captured_headers;
  bool captured_has_connection;
  std::string captured_http_auth;
  std::string captured_http_vers;
  tim_t captured_http_time[2];
  int captured_status = 0;

  app.get_("/api/v1", [&](const http_q& q, http_s& s)
  {
    handler_called = true;
    captured_url = q.url_();
    captured_url_normal = q.url_normal_();
    captured_url_prefix = q.url_prefix_();
    captured_url_rest = q.url_rest_();
    captured_url_query = q.url_query_();

    captured_queries = q.queries_();
    captured_query_token = q.query_("token");
    captured_query_name = q.query_("name");
    captured_rest_raw = q.rest_raw_();

    captured_headers = q.headers_();
    captured_has_connection = q.header_has_("connection");

    captured_http_vers = q.vers_();
    captured_http_auth = q.http_auth_();
    captured_http_time[0] = q.http_time_0_();
    captured_http_time[1] = q.http_time_1_();

    s.status_(200);
    s.send_text_("OK");
    captured_status = s.h2o_request->res.status;
  }, false); // sync mode

  // Start server
  app.start_();

  // Wait for server to be ready
  assert(http_t::ping_("127.0.0.1", 18096) == 0);

  // Send request with complex URL
  std::cout << "Sending request ..." << std::endl;
  std::string response = http_t::request_("127.0.0.1", 18096, "GET", "/api/v2/../v1/m5472/a%205472?token=xxx&name=John%20Doe");

  // Wait longer for handler to process
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // Verify handler was called
  if (!handler_called) {
    std::cerr << "\n✗ ERROR: Handler was not called." << std::endl;
    std::cerr << "Response preview: " << response.substr(0, 300) << std::endl;
    std::cerr << "Full response: " << response << std::endl;
    app.stop_();
    return 1;
  }
  std::cout << "✓ Handler was called" << std::endl;

  // Verify URL fields
  assert(captured_url == "/api/v2/../v1/m5472/a%205472?token=xxx&name=John%20Doe");
  std::cout << "✓ url field correct: " << captured_url << std::endl;

  assert(captured_url_normal == "/api/v1/m5472/a 5472"); // h2o decodes path here
  std::cout << "✓ url_normal field correct: " << captured_url_normal << std::endl;

  assert(captured_url_prefix == "/api/v1");
  std::cout << "✓ url_prefix field correct: " << captured_url_prefix << std::endl;

  assert(captured_url_rest == "/m5472/a 5472"); // h2o decodes path here
  std::cout << "✓ url_rest field correct: " << captured_url_rest << std::endl;

  assert(captured_url_query == "?token=xxx&name=John%20Doe");
  std::cout << "✓ url_query field correct: " << captured_url_query << std::endl;

  assert(captured_queries.size() == 2);
  std::cout << "✓ queries field correct: " << captured_queries.size() << std::endl;

  assert(captured_query_token == "xxx");
  std::cout << "✓ query_(\"token\") field correct: " << captured_query_token << std::endl;

  assert(captured_query_name == "John%20Doe");
  std::cout << "✓ query_(\"name\") field correct: " << captured_query_name << std::endl;

  assert(http_q::decode_(captured_query_name) == "John Doe");
  std::cout << "✓ query_(\"name\") field decoded: " << http_q::decode_(captured_query_name) << std::endl;

  assert(http_q::encode_("John Doe") == "John%20Doe");
  std::cout << "✓ encode_(\"John Doe\") field encoded: " << http_q::encode_("John Doe") << std::endl;

  assert(captured_rest_raw == "/m5472/a%205472?token=xxx&name=John%20Doe");
  std::cout << "✓ rest_raw_() field correct: " << captured_rest_raw << std::endl;

  std::cout << "captured_headers # = " << captured_headers.size() << std::endl;
  int i = 0;
  for (const auto& [key, value] : captured_headers) {
    std::cout << "  #" << i << " " << key << " = " << value << std::endl;
    i++;
  }
  assert(captured_has_connection);
  assert(captured_headers.find("connection") != captured_headers.end());

  std::cout << "captured_http_auth: " << captured_http_auth << std::endl;
  std::cout << "captured_http_vers: " << captured_http_vers << std::endl;
  std::cout << "captured_http_time[0]: " << captured_http_time[0].dump_() << std::endl;
  std::cout << "captured_http_time[1]: " << captured_http_time[1].dump_() << std::endl;

  // Verify response status
  assert(captured_status == 200);
  std::cout << "✓ Status set to 200" << std::endl;

  // Verify HTTP response
  http_r r(response);
  std::cout << "Response:\n" << response << std::endl;
  std::cout << "DEBUG: Response status: " << r.status << std::endl;
  std::cout << "DEBUG: Response content:\n" << r.body << "\n" << std::endl;
  std::cout << "DEBUG: Response length: " << r.body.length() << std::endl;

  assert(http_t::response_is_(response, 200, "OK"));
  std::cout << "✓ HTTP response is 200 OK with correct body" << std::endl;

  // next round
  http_t::request_("127.0.0.1", 18096, "GET", "/api/v2/../v1?fuk=you");
  std::cout << "captured_rest_raw: " << captured_rest_raw << std::endl;
  assert(captured_rest_raw == "?fuk=you");
  std::cout << "✓ rest_raw_() field correct: " << captured_rest_raw << std::endl;
  std::cout << "captured_url_rest: " << captured_url_rest << std::endl;
  assert(captured_status == 200);
  http_t::request_("127.0.0.1", 18096, "GET", "/api/v2/../v1/");
  assert(captured_rest_raw == "");
  std::cout << "✓ rest_raw_() field correct: " << captured_rest_raw << std::endl;
  std::cout << "captured_url_rest: " << captured_url_rest << std::endl;
  assert(captured_status == 200);
  http_t::request_("127.0.0.1", 18096, "GET", "/api/v2/../v1");
  assert(captured_rest_raw == "");
  std::cout << "✓ rest_raw_() field correct: " << captured_rest_raw << std::endl;
  std::cout << "captured_url_rest: " << captured_url_rest << std::endl;
  assert(captured_status == 200);

  app.stop_();
}

std::cout << "\n=== Test 17: Complete Thread Pool Workflow ===" << std::endl;
{
  std::ifstream cert_file("httptest0v1t17.crt");
  std::ifstream key_file("httptest0v1t17.key");
  if (!cert_file.good() || !key_file.good())
  {
    std::cout << "Generating self-signed certificates..." << std::endl;
    // openssl req -x509 -newkey rsa:2048 -keyout httptest0v1t17.key -out httptest0v1t17.crt -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=Fuk Organization/OU=Dev/CN=localhost/emailAddress=fuck@mail.com"
    int result = system("openssl req -x509 -newkey rsa:2048 -keyout httptest0v1t17.key -out httptest0v1t17.crt -days 365 -nodes -subj \"/C=US/ST=California/L=San Francisco/O=Fuk Organization/OU=Dev/CN=localhost/emailAddress=fuck@mail.com\" 2>/dev/null");
    if (result != 0)
    {
      std::cerr << "Failed to generate SSL certificates. Please ensure OpenSSL is installed." << std::endl;
      return 1;
    }
    std::cout << "✓ SSL certificates generated: httptest0v1t17.crt, httptest0v1t17.key" << std::endl;
  }
  else
  {
    std::cout << "✓ SSL certificates already exist" << std::endl;
  }

  http_a app;

  app.ssl_("httptest0v1t17.crt", "httptest0v1t17.key");

  // Setup listeners
  app.listen_("127.0.0.1", 18097);
  app.listen_("127.0.0.1", 18098);
  assert(app.listeners.size() == 2);
  std::cout << "✓ Multiple listeners configured" << std::endl;

  // Register comprehensive routes
  app.get_("/api/health", [](const http_q& q, http_s& s) {
    s.status_(200);
    s.send_json_(std::string("{\"status\":\"healthy\",\"method\":\"GET\"}"));
  }, false); // sync mode

  app.post_("/api/data", [](const http_q& q, http_s& s) {
    s.status_(201);
    s.send_json_(std::string("{\"action\":\"created\",\"method\":\"POST\"}"));
  }, false); // sync mode

  app.put_("/api/update", [](const http_q& q, http_s& s) {
    s.status_(200);
    s.send_json_(std::string("{\"action\":\"updated\",\"method\":\"PUT\"}"));
  }, false); // sync mode

  app.delete_("/api/remove", [](const http_q& q, http_s& s) {
    s.status_(204);
    s.send_(""); // No content response
  }, false); // sync mode

  app.get_("/api/echo", [](const http_q& q, http_s& s) {
    s.status_(200);
    nlohmann::json response = {
      {"url", std::string(q.url)},
      {"url_normal", std::string(q.url_normal)},
      {"url_prefix", std::string(q.url_prefix)},
      {"url_rest", std::string(q.url_rest)},
      {"url_query", std::string(q.url_query)}
    };
    s.send_json_(response);  // Pass nlohmann::json directly
  }, false); // sync mode

  assert(app.prefix_groups.size() == 5);
  std::cout << "✓ All routes registered successfully" << std::endl;

  // Start server using thread pool (non-blocking)
  assert(app.state.load() == 1); // initialized
  assert(app.uptime_() == 0); // uptime should be 0

  app.start_(); // Launches serve_() in thread

  assert(http_t::ping_("127.0.0.1", 18097) == 0);
  assert(app.state.load() == 2); // serving
  std::cout << "✓ Server started in thread pool worker thread" << std::endl;

  // Wait for server to be ready
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  assert(app.uptime_() > 0); // uptime should be greater than 0

  // Test comprehensive HTTP interactions
  std::vector<std::pair<std::string, std::string>> tests = {
    {"GET /api/health HTTP/1.1", "/api/health"},
    {"POST /api/data HTTP/1.1", "/api/data"},
    {"PUT /api/update HTTP/1.1", "/api/update"},
    {"DELETE /api/remove HTTP/1.1", "/api/remove"},
    {"GET /api/echo?test=123 HTTP/1.1", "/api/echo?test=123"}
  };

  for (const auto& [method_path, url] : tests) {
    std::string method = method_path.substr(0, method_path.find(' '));
    std::string path = url;

    std::string response = http_t::request_("127.0.0.1", 18097, method, path, "", {}, 0, true);

    if (method == "GET" && path == "/api/health") {
      assert(http_t::response_is_(response, 200, "{\"status\":\"healthy\",\"method\":\"GET\"}"));
    } else if (method == "POST" && path == "/api/data") {
      assert(http_t::response_is_(response, 201, "{\"action\":\"created\",\"method\":\"POST\"}"));
    } else if (method == "PUT" && path == "/api/update") {
      assert(http_t::response_is_(response, 200, "{\"action\":\"updated\",\"method\":\"PUT\"}"));
    } else if (method == "DELETE" && path == "/api/remove") {
      assert(http_t::response_is_(response, 204, ""));
    } else if (method == "GET" && path == "/api/echo?test=123") {
      // Echo test - verify 200 status and basic JSON structure
      assert(http_t::response_is_(response, 200));
      assert(response.find("\"url\":\"/api/echo?test=123\"") != std::string::npos);
      assert(response.find("\"url_query\":\"?test=123\"") != std::string::npos);
    }

    std::cout << "✓ " << method << " " << path << " - HTTP " << (method == "DELETE" ? 204 : 200) << std::endl;
  }

  // Test second port (same server, different port)
  std::string health_check = http_t::request_("127.0.0.1", 18098, "GET", "/api/health", "", {}, 0, true);
  assert(http_t::response_is_(health_check, 200, "{\"status\":\"healthy\",\"method\":\"GET\"}"));
  std::cout << "✓ Second listener port working correctly" << std::endl;

  // Stop server (thread pool will handle cleanup)
  app.stop_();
  assert(app.uptime_() == 0); // uptime should be 0
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  assert(app.state.load() == 3); // stopped
  std::cout << "✓ Server stopped gracefully" << std::endl;

  // Test server restart workflow
  std::cout << "\n--- Testing Server Restart ---" << std::endl;

  app.listen_("127.0.0.1", 18097);
  assert(app.listeners.size() == 1);
  std::cout << "✓ Listener added after stop" << std::endl;

  // Restart the server (should use restart logic)
  assert(app.state.load() == 3); // should be stopped
  app.start_(); // restart from stopped state
  assert(app.state.load() == 2); // serving again
  assert(app.server_a.load()); // server thread alive
  std::cout << "✓ Server restarted successfully" << std::endl;

  // Wait for restart to be ready
  assert(http_t::ping_("127.0.0.1", 18097) == 0);

  // Test that restarted server still works
  std::string restart_check = http_t::request_("127.0.0.1", 18097, "GET", "/api/health", "", {}, 0, true);
  assert(http_t::response_is_(restart_check, 200, "{\"status\":\"healthy\",\"method\":\"GET\"}"));
  std::cout << "✓ Restarted server responding correctly" << std::endl;

  // Stop server again
  app.stop_();
  assert(app.uptime_() == 0);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  assert(app.state.load() == 3); // stopped again
  std::cout << "✓ Server stopped again gracefully" << std::endl;

  // Test signal handling
  std::cout << "\n--- Testing Signal Handling ---" << std::endl;

  app.listen_("127.0.0.1", 18098);
  assert(app.listeners.size() == 1);
  std::cout << "✓ Listener added before start" << std::endl;

  // Set up signal handling
  app.signal_();
  std::cout << "✓ Signal handling configured" << std::endl;

  // Start server again
  app.start_();
  assert(app.state.load() == 2);
  assert(app.server_a.load());
  std::cout << "✓ Server started for signal test" << std::endl;

  // Wait for server to be ready
  assert(http_t::ping_("127.0.0.1", 18098) == 0);

  // Test that server is responding before signal
  std::string pre_signal_check = http_t::request_("127.0.0.1", 18098, "GET", "/api/health", "", {}, 0, true);
  assert(http_t::response_is_(pre_signal_check, 200, "{\"status\":\"healthy\",\"method\":\"GET\"}"));
  std::cout << "✓ Server responding before signal" << std::endl;

  // Wait for manual Ctrl+C signal or timeout with automatic signal
  std::cout << "Server is running...\n\nPress Ctrl+C to test signal handling (will auto-signal after 7 seconds)" << std::endl;

  // Wait up to 7 seconds for server to stop (manual Ctrl+C) or send signal automatically
  bool manual_signal = false;
  auto start_wait = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start_wait < std::chrono::seconds(7)) {
    if (app.state.load() == 3) {
      manual_signal = true;
      std::cout << "✓ Server stopped by manual Ctrl+C" << std::endl;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  // If no manual signal, send SIGINT automatically
  if (!manual_signal) {
    std::cout << "No manual Ctrl+C received, sending SIGINT automatically..." << std::endl;
    kill(getpid(), SIGINT);
    // Wait a bit for signal processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  // Verify server stopped due to signal
  assert(app.state.load() == 3); // should be stopped
  assert(app.uptime_() >= 0); // uptime should be valid
  std::cout << "✓ Server stopped gracefully via signal" << std::endl;

  // Verify server is no longer accepting connections
  bool port_closed = false;
  for (int i = 0; i < 10; ++i) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18098);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
      port_closed = true;
      close(sock);
      break;
    }
    close(sock);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  assert(port_closed);
  std::cout << "✓ Server port closed after signal" << std::endl;

  // Finalize everything
  app.fina_();
  assert(app.state.load() == 0); // finalized
  std::cout << "✓ Complete cleanup successful" << std::endl;

  std::remove("httptest0v1t17.crt");
  std::remove("httptest0v1t17.key");
}

std::cout << "\n=== All Workflow Tests Passed! ===" << std::endl;
return 0;

}
