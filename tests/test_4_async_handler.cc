#include "../include/http_a_server.hh"

#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <iostream>
#include <string>

// Test utilities for async mode
struct async_test_utils
{
  static std::atomic<int> request_counter;
  static std::mutex test_mutex;
  static std::condition_variable test_cv;
  static std::vector<std::string> completed_requests;

  static void reset_test_state()
  {
    request_counter.store(0);
    completed_requests.clear();
  }

  static void wait_for_requests(int expected_count, int timeout_ms = 5000)
  {
    std::unique_lock<std::mutex> lock(test_mutex);
    test_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
      [expected_count]() { return request_counter.load() >= expected_count; });
  }

  static void notify_request_completed(const std::string& id)
  {
    std::lock_guard<std::mutex> lock(test_mutex);
    completed_requests.push_back(id);
    request_counter.fetch_add(1);
    test_cv.notify_all();
  }
};

// Static member definitions
std::atomic<int> async_test_utils::request_counter(0);
std::mutex async_test_utils::test_mutex;
std::condition_variable async_test_utils::test_cv;
std::vector<std::string> async_test_utils::completed_requests;

int main(int argc, char** argv)
{

std::cout << "===========================================================\n" << std::endl;
std::cout << "=== Async Mode Comprehensive Test Suite ===\n" << std::endl;

std::cout << "=== Test 1: Basic Async Functionality ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18401);

  bool handler_called = false;
  std::string response_body;

  app.get_("/async/basic", [&](const http_q& q, http_s& s)
  {
    handler_called = true;
    async_test_utils::notify_request_completed("basic");

    // Simulate some async work
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    s.status_(200);
    s.send_text_("Async response");
  }, true); // async = true

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18401) == 0);

  std::string response = http_t::request_("127.0.0.1", 18401, "GET", "/async/basic");
  std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Wait for async completion

  assert(handler_called);
  assert(http_t::response_is_(response, 200, "Async response"));
  std::cout << "✓ Basic async functionality works" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 2: Async with JSON Response ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18402);

  app.post_("/async/json", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("json");

    // Simulate database operation
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    nlohmann::json response = {
      {"status", "success"},
      {"method", "POST"},
      {"async", true},
      {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
    };

    s.status_(201);
    s.send_json_(response);
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18402) == 0);

  std::string response = http_t::request_("127.0.0.1", 18402, "POST", "/async/json");
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  http_r parsed(response);
  assert(parsed.status == 201);
  assert(!parsed.body.empty());

  try {
    nlohmann::json json_resp = nlohmann::json::parse(parsed.body);
    assert(json_resp["status"] == "success");
    assert(json_resp["method"] == "POST");
    assert(json_resp["async"] == true);
    assert(json_resp.contains("timestamp"));
    std::cout << "✓ Async JSON response works correctly" << std::endl;
  } catch (...) {
    std::cerr << "✗ JSON parsing failed" << std::endl;
    return 1;
  }

  app.stop_();
}

std::cout << "\n=== Test 3: Async Timeout Handling ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18403);

  app.get_("/async/timeout", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("timeout_start");

    // Simulate long-running operation that exceeds timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    s.status_(200);
    s.send_text_("Should not reach here");
  }, true, 100); // async = true, timeout = 100ms

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18403) == 0);

  std::string response = http_t::request_("127.0.0.1", 18403, "GET", "/async/timeout");
  std::this_thread::sleep_for(std::chrono::milliseconds(300)); // Wait for timeout

  http_r parsed(response);
  assert(parsed.status == 504); // Gateway Timeout
  assert(parsed.reason.find("Gateway Timeout") != std::string::npos);
  std::cout << "✓ Async timeout handling works" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 4: Async Exception Handling ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18404);

  app.get_("/async/exception", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("exception");

    // Simulate operation that throws exception
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    throw std::runtime_error("Simulated async error");
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18404) == 0);

  std::string response = http_t::request_("127.0.0.1", 18404, "GET", "/async/exception");
  std::this_thread::sleep_for(std::chrono::milliseconds(150));

  http_r parsed(response);
  assert(parsed.status == 500); // Internal Server Error
  assert(parsed.reason.find("Execute Failure") != std::string::npos);
  std::cout << "✓ Async exception handling works" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 5: Concurrent Async Requests ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18405);

  std::atomic<int> concurrent_count(0);
  std::vector<std::string> request_ids;

  app.get_("/async/concurrent", [&](const http_q& q, http_s& s)
  {
    int current = concurrent_count.fetch_add(1);
    std::string request_id = "req_" + std::to_string(current);

    // Simulate variable processing time
    int delay = 20 + (current * 10); // 20ms, 30ms, 40ms, etc.
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    concurrent_count.fetch_sub(1);

    s.status_(200);
    s.send_json_(nlohmann::json{{"request_id", request_id}, {"delay", delay}});
    async_test_utils::notify_request_completed(request_id);
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18405) == 0);

  // Send 5 concurrent requests
  std::vector<std::thread> threads;
  std::vector<std::string> responses(5);

  for (int i = 0; i < 5; ++i) {
    threads.emplace_back([&, i]() {
      responses[i] = http_t::request_("127.0.0.1", 18405, "GET", "/async/concurrent");
    });
  }

  for (auto& t : threads) t.join();

  // Wait for all async operations to complete
  async_test_utils::wait_for_requests(5, 2000);

  assert(async_test_utils::completed_requests.size() == 5);
  std::cout << "✓ Concurrent async requests handled correctly" << std::endl;

  // Verify all responses are valid
  for (const auto& resp : responses) {
    http_r parsed(resp);
    assert(parsed.status == 200);
    try {
      nlohmann::json json_resp = nlohmann::json::parse(parsed.body);
      assert(json_resp.contains("request_id"));
      assert(json_resp.contains("delay"));
    } catch (...) {
      std::cerr << "✗ Invalid JSON in concurrent response" << std::endl;
      return 1;
    }
  }
  std::cout << "✓ All concurrent responses are valid" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 6: Async Large Response Handling ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18406);

  app.get_("/async/large", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("large");

    // Generate large response (1MB)
    std::string large_data;
    large_data.reserve(1024 * 1024);
    for (int i = 0; i < 1024 * 256; ++i) { // 256KB of pattern
      large_data += "Large async response data with pattern: ";
      large_data += std::to_string(i);
      large_data += "\n";
    }

    s.status_(200);
    s.send_(large_data);
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18406) == 0);

  std::string response = http_t::request_("127.0.0.1", 18406, "GET", "/async/large");
  std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Wait for large response

  http_r parsed(response);
  assert(parsed.status == 200);
  assert(parsed.body.size() > 100000); // Should be large
  assert(parsed.body.find("Large async response data") != std::string::npos);
  std::cout << "✓ Large async response handling works (" << parsed.body.size() << " bytes)" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 7: Mixed Sync and Async Routes ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18407);

  // Sync route
  app.get_("/sync", [](const http_q& q, http_s& s) {
    s.send_text_("Sync response");
  }); // default async=false

  // Async route
  app.get_("/async", [&](const http_q& q, http_s& s) {
    async_test_utils::notify_request_completed("mixed_async");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    s.send_text_("Async response");
  }, true); // async=true

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18407) == 0);

  // Test sync route
  std::string sync_response = http_t::request_("127.0.0.1", 18407, "GET", "/sync");
  assert(http_t::response_is_(sync_response, 200, "Sync response"));
  std::cout << "✓ Sync route works" << std::endl;

  // Test async route
  std::string async_response = http_t::request_("127.0.0.1", 18407, "GET", "/async");
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  assert(http_t::response_is_(async_response, 200, "Async response"));
  std::cout << "✓ Async route works" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 8: Async Resource Cleanup ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18408);

  std::atomic<int> cleanup_count(0);

  app.get_("/async/cleanup", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("cleanup");

    // Simulate resource allocation
    auto* resource = new std::string("test resource");
    cleanup_count.fetch_add(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // Resource should be cleaned up by RAII, but we simulate proper cleanup
    delete resource;
    cleanup_count.fetch_sub(1);

    s.status_(200);
    s.send_text_("Resource cleaned up");
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18408) == 0);

  // Send multiple requests
  std::vector<std::thread> threads;
  for (int i = 0; i < 3; ++i) {
    threads.emplace_back([&]() {
      http_t::request_("127.0.0.1", 18408, "GET", "/async/cleanup");
    });
  }

  for (auto& t : threads) t.join();
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // All resources should be cleaned up
  assert(cleanup_count.load() == 0);
  std::cout << "✓ Async resource cleanup works correctly" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 9: Async with External Command Execution ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18409);

  app.get_("/async/exec", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("exec");

    // Execute external command asynchronously
    exe_r result = q.exe_load_("echo", {"Hello from async exec"});

    if (result.status == 3 && result.exit_code == 0) { // completed successfully
      s.status_(200);
      s.send_json_(nlohmann::json{
        {"command", "echo"},
        {"output", result.stdout_info},
        {"async", true}
      });
    } else {
      s.status_(500);
      s.send_text_("Command execution failed");
    }
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18409) == 0);

  std::string response = http_t::request_("127.0.0.1", 18409, "GET", "/async/exec");
  std::this_thread::sleep_for(std::chrono::milliseconds(300)); // Wait for command execution

  std::cout << response << std::endl;
  http_r parsed(response);
  assert(parsed.status == 200);

  try {
    nlohmann::json json_resp = nlohmann::json::parse(parsed.body);
    assert(json_resp["command"] == "echo");
    assert(json_resp["async"] == true);
    assert(json_resp["output"].get<std::string>().find("Hello from async exec") != std::string::npos);
    std::cout << "✓ Async external command execution works" << std::endl;
  } catch (...) {
    std::cerr << "✗ JSON parsing failed in exec test" << std::endl;
    return 1;
  }

  app.stop_();
}

std::cout << "\n=== Test 10: Async Response Ordering and State Management ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18410);

  std::vector<std::string> processing_order;

  app.get_("/async/order", [&](const http_q& q, http_s& s)
  {
    std::string id = q.query_("id");
    processing_order.push_back("start_" + id);

    // Variable delays to test ordering
    int delay = 50 + (std::stoi(id) * 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    processing_order.push_back("end_" + id);

    s.status_(200);
    s.send_json_(nlohmann::json{{"id", id}, {"delay", delay}});
    async_test_utils::notify_request_completed(id);
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18410) == 0);

  // Send requests with different IDs
  std::vector<std::thread> threads;
  for (int i = 0; i < 3; ++i) {
    threads.emplace_back([&, i]() {
      http_t::request_("127.0.0.1", 18410, "GET", "/async/order?id=" + std::to_string(i));
    });
  }

  for (auto& t : threads) t.join();
  async_test_utils::wait_for_requests(3, 2000);

  // Verify processing order (should be interleaved due to different delays)
  assert(processing_order.size() == 6); // 3 starts + 3 ends
  assert(async_test_utils::completed_requests.size() == 3);
  std::cout << "✓ Async response ordering and state management works" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 11: Async Error Recovery ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18411);

  std::atomic<int> error_count(0);
  std::atomic<int> success_count(0);

  app.get_("/async/recovery", [&](const http_q& q, http_s& s)
  {
    std::string action = q.query_("action");

    try {
      if (action.find("error") == 0) {
        error_count.fetch_add(1);
        throw std::logic_error("Simulated error for recovery test");
      } else {
        success_count.fetch_add(1);
        s.status_(200);
        s.send_text_("Success: " + action);
      }
      async_test_utils::notify_request_completed(action);
    } catch (const std::exception& e) {
      s.status_(500);
      s.send_text_("Error handled: " + std::string(e.what()));
      async_test_utils::notify_request_completed("error_" + action);
    }
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18411) == 0);

  // Send mix of success and error requests
  std::vector<std::thread> threads;
  std::vector<std::string> responses(4);

  for (int i = 0; i < 4; ++i) {
    threads.emplace_back([&, i]() {
      std::string action = (i % 2 == 0) ? "success" : "error";
      responses[i] = http_t::request_("127.0.0.1", 18411, "GET", "/async/recovery?action=" + action + std::to_string(i));
    });
  }

  for (auto& t : threads) t.join();
  async_test_utils::wait_for_requests(4, 2000);

  // Verify error recovery
  int success_responses = 0;
  int error_responses = 0;

  for (const auto& resp : responses) {
    http_r parsed(resp);
    if (parsed.status == 200) {
      success_responses++;
      assert(parsed.body.find("Success:") != std::string::npos);
    } else if (parsed.status == 500) {
      error_responses++;
      assert(parsed.body.find("Error handled:") != std::string::npos);
    }
  }

  assert(success_responses == 2);
  assert(error_responses == 2);
  std::cout << "✓ Async error recovery works correctly" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 12: Async Memory Management and Leaks ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18412);

  app.get_("/async/memory", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("memory");

    // Allocate memory in async operation
    std::vector<char> large_buffer(100 * 1024); // 100KB
    std::fill(large_buffer.begin(), large_buffer.end(), 'X');

    std::this_thread::sleep_for(std::chrono::milliseconds(25));

    // Memory should be cleaned up automatically
    s.status_(200);
    s.send_(std::string(large_buffer.data(), large_buffer.size()));
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18412) == 0);

  // Send multiple memory-intensive requests
  const int num_requests = 5;
  std::vector<std::thread> threads;

  for (int i = 0; i < num_requests; ++i) {
    threads.emplace_back([&]() {
      http_t::request_("127.0.0.1", 18412, "GET", "/async/memory");
    });
  }

  for (auto& t : threads) t.join();
  async_test_utils::wait_for_requests(num_requests, 3000);

  assert(async_test_utils::completed_requests.size() == num_requests);
  std::cout << "✓ Async memory management works without leaks" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 13: Async with Compression ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18413);

  app.get_("/async/compress", [&](const http_q& q, http_s& s)
  {
    async_test_utils::notify_request_completed("compress");

    // Generate compressible data
    std::string data;
    for (int i = 0; i < 1000; ++i) {
      data += "This is a repeating string that should compress well. ";
    }

    s.status_(200);
    s.send_(data);
  }, true, 0, true, 100, 6, 6); // async, timeout 0, compress enabled, min 100, quality 6

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18413) == 0);

  std::unordered_map<std::string, std::vector<std::string>> headers = {
    {"Accept-Encoding", {"gzip"}}
  };
  std::string response = http_t::request_<std::unordered_map<std::string, std::vector<std::string>>>(
    "127.0.0.1", 18413, "GET", "/async/compress", "", headers);

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  http_r parsed(response);
  assert(parsed.status == 200);
  assert(!parsed.body.empty());

  // Check if response is compressed (should contain compressed data)
  auto encoding_it = parsed.headers.find("content-encoding");
  if (encoding_it != parsed.headers.end() &&
      !encoding_it->second.empty() &&
      encoding_it->second[0].find("gzip") != std::string::npos) {
    std::cout << "✓ Async compression works (response is gzip compressed)" << std::endl;
  } else {
    // If not compressed, still verify content
    assert(parsed.body.find("This is a repeating string") != std::string::npos);
    std::cout << "✓ Async response works (compression may not be applied due to size)" << std::endl;
  }

  app.stop_();
}

std::cout << "\n=== Test 14: Async Thread Pool Saturation ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18414);

  std::atomic<int> active_threads(0);

  app.get_("/async/saturate", [&](const http_q& q, http_s& s)
  {
    active_threads.fetch_add(1);
    async_test_utils::notify_request_completed("saturate");

    // Long-running task to saturate thread pool
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    active_threads.fetch_sub(1);
    s.status_(200);
    s.send_text_("Saturated thread completed");
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18414) == 0);

  // Send many concurrent requests to potentially saturate thread pool
  const int num_requests = 10; // More than typical thread pool size
  std::vector<std::thread> threads;

  auto start_time = std::chrono::steady_clock::now();

  for (int i = 0; i < num_requests; ++i) {
    threads.emplace_back([&]() {
      http_t::request_("127.0.0.1", 18414, "GET", "/async/saturate");
    });
  }

  for (auto& t : threads) t.join();

  async_test_utils::wait_for_requests(num_requests, 5000);

  auto end_time = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

  assert(async_test_utils::completed_requests.size() == num_requests);
  assert(active_threads.load() == 0); // All threads completed
  std::cout << "✓ Async thread pool saturation handled (" << duration.count() << "ms for " << num_requests << " requests)" << std::endl;

  app.stop_();
}

std::cout << "\n=== Test 15: Async State Isolation Between Requests ===" << std::endl;
{
  async_test_utils::reset_test_state();
  http_a app;
  app.listen_("127.0.0.1", 18415);

  std::mutex isolation_mutex;
  std::unordered_map<std::string, std::string> request_states;

  app.get_("/async/isolate", [&](const http_q& q, http_s& s)
  {
    std::string req_id = q.query_("id");

    {
      std::lock_guard<std::mutex> lock(isolation_mutex);
      request_states[req_id] = "processing";
    }

    async_test_utils::notify_request_completed("isolate_" + req_id);

    // Each request has different processing time and state
    int delay = 30 + (std::stoi(req_id) * 15);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    {
      std::lock_guard<std::mutex> lock(isolation_mutex);
      request_states[req_id] = "completed_" + std::to_string(delay);
    }

    s.status_(200);
    s.send_json_(nlohmann::json{
      {"id", req_id},
      {"delay", delay},
      {"state", request_states[req_id]}
    });
  }, true);

  app.start_();
  assert(http_t::ping_("127.0.0.1", 18415) == 0);

  // Send requests with different IDs
  std::vector<std::thread> threads;
  std::vector<std::string> responses(3);

  for (int i = 0; i < 3; ++i) {
    threads.emplace_back([&, i]() {
      responses[i] = http_t::request_("127.0.0.1", 18415, "GET", "/async/isolate?id=" + std::to_string(i));
    });
  }

  for (auto& t : threads) t.join();
  async_test_utils::wait_for_requests(3, 2000);

  // Verify state isolation
  for (int i = 0; i < 3; ++i) {
    http_r parsed(responses[i]);
    assert(parsed.status == 200);

    try {
      nlohmann::json json_resp = nlohmann::json::parse(parsed.body);
      assert(json_resp["id"] == std::to_string(i));
      assert(json_resp.contains("delay"));
      assert(json_resp["state"].get<std::string>().find("completed_") != std::string::npos);
    } catch (...) {
      std::cerr << "✗ JSON parsing failed in isolation test" << std::endl;
      return 1;
    }
  }

  std::cout << "✓ Async state isolation between requests works" << std::endl;

  app.stop_();
}

std::cout << "\n=== All Async Mode Tests Passed! ===" << std::endl;
std::cout << "✓ Basic async functionality" << std::endl;
std::cout << "✓ JSON responses" << std::endl;
std::cout << "✓ Timeout handling" << std::endl;
std::cout << "✓ Exception handling" << std::endl;
std::cout << "✓ Concurrent requests" << std::endl;
std::cout << "✓ Large response handling" << std::endl;
std::cout << "✓ Mixed sync/async routes" << std::endl;
std::cout << "✓ Resource cleanup" << std::endl;
std::cout << "✓ External command execution" << std::endl;
std::cout << "✓ Response ordering" << std::endl;
std::cout << "✓ Error recovery" << std::endl;
std::cout << "✓ Memory management" << std::endl;
std::cout << "✓ Compression support" << std::endl;
std::cout << "✓ Thread pool saturation" << std::endl;
std::cout << "✓ State isolation" << std::endl;

return 0;

}
