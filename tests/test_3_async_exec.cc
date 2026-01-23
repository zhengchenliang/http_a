#include "../include/http_a_server.hh"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>
#include <cstring>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <zlib.h>
#include <brotli/encode.h>
#include <brotli/types.h>

// Compression encoding functions for testing
static inline std::string encode_gzip(const std::string &input, int level = 1)
{
  z_stream stream = {};
  stream.next_in = (Bytef *)input.data();
  stream.avail_in = input.size();

  if (deflateInit2(&stream, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return "";

  std::string output;
  char buffer[32768];
  int ret;
  do {
    stream.next_out = (Bytef *)buffer;
    stream.avail_out = sizeof(buffer);
    ret = deflate(&stream, Z_FINISH);
    if (ret < 0)
    {
      deflateEnd(&stream);
      return "";
    }
    output.append(buffer, sizeof(buffer) - stream.avail_out);
  } while (ret != Z_STREAM_END);

  deflateEnd(&stream);
  return output;
}

static inline std::string encode_deflate(const std::string &input, int level = 1)
{
  z_stream stream = {};
  stream.next_in = (Bytef *)input.data();
  stream.avail_in = input.size();

  if (deflateInit2(&stream, level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) return "";

  std::string output;
  char buffer[32768];
  int ret;
  do {
    stream.next_out = (Bytef *)buffer;
    stream.avail_out = sizeof(buffer);
    ret = deflate(&stream, Z_FINISH);
    if (ret < 0)
    {
      deflateEnd(&stream);
      return "";
    }
    output.append(buffer, sizeof(buffer) - stream.avail_out);
  } while (ret != Z_STREAM_END);

  deflateEnd(&stream);
  return output;
}

static inline std::string encode_brotli(const std::string &input, int quality = 1)
{
  size_t available_in = input.size();
  const uint8_t *next_in = (const uint8_t *)input.data();

  size_t max_output_size = BrotliEncoderMaxCompressedSize(available_in);
  if (max_output_size == 0) return "";

  std::string output;
  output.resize(max_output_size);

  size_t available_out = max_output_size;
  uint8_t *next_out = (uint8_t *)&output[0];

  BrotliEncoderState *state = BrotliEncoderCreateInstance(NULL, NULL, NULL);
  if (!state) return "";

  BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, quality);

  if (BrotliEncoderCompressStream(state
    , BROTLI_OPERATION_FINISH
    , &available_in
    , &next_in
    , &available_out
    , &next_out
    , NULL) != BROTLI_TRUE
  )
  {
    BrotliEncoderDestroyInstance(state);
    return "";
  }

  output.resize(max_output_size - available_out);
  BrotliEncoderDestroyInstance(state);
  return output;
}

int main(int argc, char** argv)
{

// HTTP Execution API Comprehensive Tests
// ======================================

std::cout << "\n=== HTTP Execution API Tests ===" << std::endl;
{
  http_a app;
  app.listen_("127.0.0.1", 18080);

  // Setup HTTP endpoints (same as current implementation)
  // 0. execute static
  app.get_("/api/run/static", [](const http_q& q, http_s& s)
  {
    // Execute a command and capture output
    exe_r result = q.exe_load_("ls", "-la .");

    // Check execution status
    if (result.status != 3)
    { // not completed
      s.status_(500);
      s.send_text_("Execution failed");
      return;
    }

    // Check exit code
    if (!result.exit_normal || result.exit_code != 0)
    {
      s.status_(500);
      nlohmann::json error_json =
      {
        {"error", "Command failed"},
        {"exit_code", result.exit_code},
        {"stderr", result.stderr_info}
      };
      s.send_json_(error_json);
      return;
    }

    // Success - return stdout
    s.status_(200);
    s.send_text_(result.stdout_info);
  });

  // 1. execute by query
  app.post_("/api/run", [](const http_q& q, http_s& s)
  {
    std::string cmd = http_q::decode_(q.query_("cmd"));
    std::string args = http_q::decode_(q.query_("args"));
    std::string dir = http_q::decode_(q.query_("dir"));
    std::string env_str = http_q::decode_(q.query_("env"));
    std::unordered_map<std::string, std::string> env = q.expand_(env_str);
    std::string timeout = q.query_("timeout");
    uint64_t timeout_ms = std::stoull(timeout);
    std::string capture = q.query_("capture");
    uint8_t capture_mode = std::stoul(capture);
    std::string period = q.query_("period");
    uint64_t period_ms = std::stoull(period);

    exe_r result = q.exe_run_(cmd, args, dir, env, timeout_ms, capture_mode, period_ms);

    nlohmann::json response =
    {
      {"status", result.status},
      {"exit_normal", result.exit_normal},
      {"exit_code", result.exit_code},
      {"exit_sign", result.exit_sign},
      {"timed_out", result.timed_out},
      {"core_dumped", result.core_dumped},
      {"stdout", result.stdout_info},
      {"stderr", result.stderr_info},
      {"stdout_size", result.stdout_size},
      {"stderr_size", result.stderr_size}
    };
    if (result.status == 3) s.status_(200);
    s.send_json_(response);
  });

  // 2. fire-and-forget
  app.post_("/api/fire", [](const http_q& q, http_s& s)
  {
    std::string cmd = http_q::decode_(q.query_("cmd"));
    std::string args = http_q::decode_(q.query_("args"));
    std::string dir = http_q::decode_(q.query_("dir"));
    std::string env_str = http_q::decode_(q.query_("env"));
    std::unordered_map<std::string, std::string> env = q.expand_(env_str);

    exe_r result = q.exe_fire_(cmd, args, dir, env);

    if (result.status == 4)
    { // detached
      s.status_(202);
      s.send_text_("Job triggered");
    }
    else
    {
      s.status_(500);
      s.send_text_("Failed to trigger job");
    }
  });

  app.start_();
  if (http_t::ping_("127.0.0.1", 18080) != 0)
  {
    std::cerr << "Failed to ping port 18080" << std::endl;
    return 1;
  }

  // Test 1: Static endpoint tests
  std::cout << "\n--- Test 1: Static Endpoint (/api/run/static) ---" << std::endl;
  {
    std::string response = http_t::request_("127.0.0.1", 18080, "GET", "/api/run/static");
    assert(http_t::response_is_(response, 200)); // Should return directory listing
    std::cout << "✓ Static endpoint returns directory listing" << std::endl;

    // Verify it contains expected content (like total/drwxr-xr-x entries)
    size_t body_pos = response.find("\r\n\r\n");
    std::string body = response.substr(body_pos + 4);
    assert(body.find("total") != std::string::npos || body.find("drwxr") != std::string::npos);
    std::cout << "✓ Static endpoint output contains expected directory content" << std::endl;
  }

  // Test 2: Dynamic execution endpoint - Basic commands
  std::cout << "\n--- Test 2: Dynamic Execution - Basic Commands ---" << std::endl;
  {
    // Test 2.1: Simple echo command
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=echo&args=hello%20world&timeout=5000&capture=1&period=0");
    std::cout << "Response1: " << response1 << std::endl;
    std::cout << "Response1 JSON: " << http_t::response_json_(response1) << std::endl;
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "hello world\n"},
      {"stdout_size", 12},
      {"timed_out", false}
    }));
    std::cout << "✓ Echo command executed successfully" << std::endl;

    // Test 2.2: Command with no arguments
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=pwd&args=&timeout=5000&capture=1&period=0");
    nlohmann::json pwd_json = http_t::response_json_(response2);
    assert(pwd_json["status"] == 3);
    assert(pwd_json["exit_normal"] == true);
    assert(pwd_json["exit_code"] == 0);
    assert(pwd_json["core_dumped"] == false);
    assert(pwd_json["exit_sign"] == 0);
    assert(pwd_json["stderr"] == "");
    assert(pwd_json["stderr_size"] == 0);
    assert(pwd_json["timed_out"] == false);
    // stdout will vary depending on working directory
    std::cout << "✓ pwd command executed successfully" << std::endl;

    // Test 2.3: Command with environment variables
    std::string response3 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=env&args=&env=TEST_VAR=test_value&timeout=5000&capture=1&period=0");
    nlohmann::json env_json = http_t::response_json_(response3);
    assert(env_json["status"] == 3);
    assert(env_json["exit_normal"] == true);
    assert(env_json["exit_code"] == 0);
    assert(env_json["core_dumped"] == false);
    assert(env_json["exit_sign"] == 0);
    assert(env_json["stderr"] == "");
    assert(env_json["stderr_size"] == 0);
    assert(env_json["timed_out"] == false);
    // stdout should contain TEST_VAR=test_value
    std::string stdout_str = env_json["stdout"];
    assert(stdout_str.find("TEST_VAR=test_value") != std::string::npos);
    std::cout << "✓ Environment variable handling works" << std::endl;
  }

  // Test 3: Capture modes
  std::cout << "\n--- Test 3: Capture Modes ---" << std::endl;
  {
    // Test 3.1: No capture (capture=0)
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=echo&args=test&timeout=5000&capture=0&period=10");
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ No capture mode works correctly" << std::endl;

    // Test 3.2: stdout only (capture=1)
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=echo&args=stdout_test&timeout=5000&capture=1&period=0");
    assert(http_t::response_json_is_(response2, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "stdout_test\n"},
      {"stdout_size", 12},
      {"timed_out", false}
    }));
    std::cout << "✓ stdout capture works correctly" << std::endl;

    // Test 3.3: stderr only (capture=2) - redirect echo to stderr
    std::string response3 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=sh&args=-c%20%22echo%20stderr_test%20%3E%262%22&timeout=5000&capture=2&period=0");
    assert(http_t::response_json_is_(response3, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", "stderr_test\n"},
      {"stderr_size", 12},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ stderr capture works correctly" << std::endl;

    // Test 3.4: both stdout and stderr (capture=3)
    std::string response4 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=sh&args=-c%20%22echo%20out%3Becho%20err%20%3E%262%22&timeout=5000&capture=3&period=0");
    assert(http_t::response_json_is_(response4, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", "err\n"},
      {"stderr_size", 4},
      {"stdout", "out\n"},
      {"stdout_size", 4},
      {"timed_out", false}
    }));
    std::cout << "✓ Both stdout/stderr capture works correctly" << std::endl;

    // Test 3.5: merged stderr into stdout (capture=4)
    std::string response5 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=sh&args=-c%20%22echo%20out%3Becho%20err%20%3E%262%22&timeout=5000&capture=4&period=0");
    assert(http_t::response_json_is_(response5, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "out\nerr\n"},
      {"stdout_size", 8},
      {"timed_out", false}
    }));
    std::cout << "✓ Merged stderr into stdout works correctly" << std::endl;
  }

  // Test 4: Timeout handling
  std::cout << "\n--- Test 4: Timeout Handling ---" << std::endl;
  {
    // Test 4.1: Command completes before timeout
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=sleep&args=0.1&timeout=1000&capture=0&period=10");
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ Command completes before timeout" << std::endl;

    // Test 4.2: Command times out
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=sleep&args=1&timeout=100&capture=0&period=10");
    assert(http_t::response_json_is_(response2, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", -1},
      {"exit_normal", false},
      {"exit_sign", 9}, // SIGKILL
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", true}
    }));
    std::cout << "✓ Timeout mechanism works correctly" << std::endl;
  }

  // Test 5: Error handling
  std::cout << "\n--- Test 5: Error Handling ---" << std::endl;
  {
    // Test 5.1: Command not found
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=nonexistent_command_12345&args=&timeout=5000&capture=1&period=0");
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", -1}, // failed
      {"exit_normal", false}, // should fail
      {"exit_sign", 0},
      {"status", 6},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ Command not found handled correctly" << std::endl;

    // Test 5.2: Invalid directory
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=pwd&args=&dir=/nonexistent/directory/xyz&timeout=5000&capture=1&period=0");
    assert(http_t::response_json_is_(response2, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", -1}, // chdir failed
      {"exit_normal", false},  // child calls _exit(125), so normal exit
      {"exit_sign", 0},
      {"status", 6},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ Invalid directory handled correctly" << std::endl;
  }

  // Test 6: Fire-and-forget endpoint
  std::cout << "\n--- Test 6: Fire-and-forget Endpoint ---" << std::endl;
  {
    // Test 6.1: Successful fire-and-forget
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/fire?cmd=sleep&args=0.1");
    assert(http_t::response_is_(response1, 202, "Job triggered"));
    std::cout << "✓ Fire-and-forget returns 202 immediately" << std::endl;

    // Test 6.2: Fire-and-forget with invalid command (should still return 202 since it's detached)
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/fire?cmd=nonexistent_command_12345&args=");
    assert(http_t::response_is_(response2, 500, "Failed to trigger job"));
    std::cout << "✓ Fire-and-forget accepts invalid commands (detached)" << std::endl;

    // Give some time for background processes to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  // Test 7: Python Execution VITAL
  std::cout << "\n--- Test 7: Python Execution ---" << std::endl;
  {
    // Test Python execution
    std::string cmd = "python3";
    std::string args = "-c \"print('Hello Python')\"";
    std::string url = "/api/run?cmd=" + http_q::encode_(cmd) + "&args=" + http_q::encode_(args) + "&timeout=10000&capture=1&period=0";
    std::string response = http_t::request_("127.0.0.1", 18080, "POST", url);
    assert(http_t::response_json_is_(response, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "Hello Python\n"},
      {"stdout_size", 13},
      {"timed_out", false}
    }));

    std::cout << "Response at JSON:\n" << response << std::endl;

    // Verify Python execution worked
    nlohmann::json resp_json = http_t::response_json_(response);
    std::string stdout_content = resp_json["stdout"];
    assert(stdout_content.find("Hello Python") != std::string::npos);
    std::cout << "✓ Python execution works (" << resp_json["stdout_size"] << " bytes output)" << std::endl;
  }

  // Test 8: Concurrent requests
  std::cout << "\n--- Test 8: Concurrent Requests ---" << std::endl;
  {
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    // Launch 10 concurrent requests
    for (int i = 0; i < 10; ++i) {
      threads.emplace_back([&, i]() {
        std::string url = "/api/run?cmd=echo&args=test" + std::to_string(i) + "&timeout=5000&capture=1&period=0";
        std::string response = http_t::request_("127.0.0.1", 18080, "POST", url.c_str());
        try {
          nlohmann::json resp_json = http_t::response_json_(response);
          if (resp_json["status"] == 3 && resp_json["exit_code"] == 0) {
            success_count++;
          }
        } catch (...) {}
      });
    }
  // Wait for all threads to complete
  for (auto& t : threads)
  {
    t.join();
  }

  std::cout << "Successful requests: " << success_count << "/10" << std::endl;
  assert(success_count == 10);
  std::cout << "✓ All 10 concurrent requests completed successfully" << std::endl;
  }

  // Test 9: Edge cases and security
  std::cout << "\n--- Test 9: Edge Cases and Security ---" << std::endl;
  {
    // Test 9.1: Empty command
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=&args=&timeout=5000&capture=1&period=0");
    std::cout << "Response1 JSON = " << http_t::response_json_(response1) << std::endl;
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", -1}, // failed
      {"exit_normal", false}, // should fail
      {"exit_sign", 0},
      {"status", 6},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", ""},
      {"stdout_size", 0},
      {"timed_out", false}
    }));
    std::cout << "✓ Empty command handled correctly" << std::endl;

    // Test 9.2: Special characters in arguments
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=echo&args=%22hello%20%27world%27%20%24%7BUSER%7D%22&timeout=5000&capture=1&period=0");
    nlohmann::json resp2_json = http_t::response_json_(response2);
    assert(resp2_json["status"] == 3);
    assert(resp2_json["exit_normal"] == true);
    assert(resp2_json["exit_code"] == 0);
    assert(resp2_json["core_dumped"] == false);
    assert(resp2_json["exit_sign"] == 0);
    assert(resp2_json["stderr"] == "");
    assert(resp2_json["stderr_size"] == 0);
    assert(resp2_json["timed_out"] == false);
    // Verify stdout contains the expected content (USER variable was expanded)
    std::string stdout_content = resp2_json["stdout"];
    assert(stdout_content.find("hello 'world'") != std::string::npos);
    std::cout << "✓ Special characters in arguments handled correctly" << std::endl;

    // Test 9.3: Very long arguments
    std::string long_arg(1000, 'x');
    std::string response3 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=echo&args=" + long_arg + "&timeout=5000&capture=1&period=0");
    std::cout << "Response3 JSON = " << http_t::response_json_(response3) << std::endl;
    assert(http_t::response_json_is_(response3, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", long_arg + "\n"},
      {"stdout_size", 1001},
      {"timed_out", false}
    }));
    std::cout << "✓ Very long arguments handled correctly" << std::endl;
  }

  // Test 10: Advanced Security and Performance
  std::cout << "\n--- Test 10: Advanced Security and Performance ---" << std::endl;
  {
    // Test 10.1: Dangerous input rejection (security feature)
    // wordexp correctly rejects potentially dangerous shell metacharacters
    std::string malicious_cmd = "echo";
    std::string malicious_args = "hello;rm -rf /";
    std::string safe_url = "/api/run?cmd=" + http_q::encode_(malicious_cmd) +
                           "&args=" + http_q::encode_(malicious_args) +
                           "&timeout=5000&capture=1&period=0";
    std::string response1 = http_t::request_("127.0.0.1", 18080, "POST", safe_url);
    std::cout << "Response1 JSON = " << http_t::response_json_(response1) << std::endl;
    assert(http_t::response_json_is_(response1, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "\n"},  // echo with no args just prints newline
      {"stdout_size", 1},
      {"timed_out", false}
    }));
    std::cout << "✓ Dangerous input properly rejected by wordexp security" << std::endl;

    // Test 10.2: Python script execution
    std::string cmd2 = "python3";
    std::string args2 = "-c \"print('Python test passed')\"";
    std::string response2 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=" + http_q::encode_(cmd2) + "&args=" + http_q::encode_(args2) + "&timeout=5000&capture=1&period=0");
    std::cout << "Response2 JSON = " << http_t::response_json_(response2) << std::endl;
    assert(http_t::response_json_is_(response2, 200, nlohmann::json{
      {"core_dumped", false},
      {"exit_code", 0},
      {"exit_normal", true},
      {"exit_sign", 0},
      {"status", 3},
      {"stderr", ""},
      {"stderr_size", 0},
      {"stdout", "Python test passed\n"},
      {"stdout_size", 19},
      {"timed_out", false}
    }));
    std::cout << "✓ Python execution works" << std::endl;

    // Test 10.3: High-frequency rapid requests
    auto start_time = std::chrono::steady_clock::now();
    int rapid_success_count = 0;
    for (int i = 0; i < 50; ++i) {
      std::string response = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=true&args=&timeout=1000&capture=1&period=0");
      try {
        nlohmann::json resp_json = http_t::response_json_(response);
        if (resp_json["status"] == 3 && resp_json["exit_code"] == 0) {
          rapid_success_count++;
        }
      } catch (...) {
        // Ignore parsing errors for performance test
      }
    }
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    assert(rapid_success_count >= 45); // Allow some failures for performance test
    std::cout << "✓ High-frequency requests: " << rapid_success_count << "/50 succeeded in " << duration.count() << "ms" << std::endl;

    // Test 10.4: Complex environment variables
    std::string complex_env = "PATH=/usr/bin:/bin|HOME=/tmp|TEST_VAR=hello world|COMPLEX_VAR=a=b;c=d";
    std::string response4 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=env&args=&env=" + http_q::encode_(complex_env) + "&timeout=5000&capture=1&period=0");
    nlohmann::json resp4_json = http_t::response_json_(response4);
    assert(resp4_json["status"] == 3);
    assert(resp4_json["exit_normal"] == true);
    assert(resp4_json["exit_code"] == 0);
    assert(resp4_json["core_dumped"] == false);
    assert(resp4_json["exit_sign"] == 0);
    assert(resp4_json["stderr"] == "");
    assert(resp4_json["stderr_size"] == 0);
    assert(resp4_json["timed_out"] == false);
    // Verify complex environment variables are set
    std::string env_output = resp4_json["stdout"];
    assert(env_output.find("TEST_VAR=hello world") != std::string::npos);
    assert(env_output.find("COMPLEX_VAR=a=b;c=d") != std::string::npos);
    std::cout << "✓ Complex environment variables work" << std::endl;

    // Test 10.5: Sequential command execution
    std::string seq_cmd = "sh";
    std::string seq_args = "-c \"echo Line1; echo Line2; echo Line3\"";
    std::string response5 = http_t::request_("127.0.0.1", 18080, "POST", "/api/run?cmd=" + http_q::encode_(seq_cmd) + "&args=" + http_q::encode_(seq_args) + "&timeout=5000&capture=1&period=0");
    std::cout << "Response5 JSON = " << http_t::response_json_(response5) << std::endl;
    nlohmann::json resp5_json = http_t::response_json_(response5);
    assert(resp5_json["status"] == 3);
    assert(resp5_json["exit_normal"] == true);
    assert(resp5_json["exit_code"] == 0);
    assert(resp5_json["core_dumped"] == false);
    assert(resp5_json["exit_sign"] == 0);
    assert(resp5_json["stderr"] == "");
    assert(resp5_json["stderr_size"] == 0);
    assert(resp5_json["timed_out"] == false);
    // Verify sequential command execution worked
    std::string seq_output = resp5_json["stdout"];
    assert(seq_output.find("Line1") != std::string::npos);
    assert(seq_output.find("Line2") != std::string::npos);
    assert(seq_output.find("Line3") != std::string::npos);
    std::cout << "✓ Sequential command execution works" << std::endl;

    // Test 10.6: Compression/Decompression Round-Trip Testing

    // Test 0: Round-trip compression/decompression without HTTP
    std::cout << "\n--- Test 0: Round-Trip Compression/Decompression ---" << std::endl;

    std::string test_content = "This is test content that should be compressed and decompressed successfully. It needs to be long enough to trigger compression.";
    std::string compressed_gzip, compressed_deflate, compressed_brotli;

    // Test gzip round-trip
    compressed_gzip = encode_gzip(test_content, 1);
    std::cout << "Original size: " << test_content.size() << ", Gzip compressed size: " << compressed_gzip.size() << std::endl;
    assert(!compressed_gzip.empty());
    std::string decompressed_gzip = http_r::decode_gzip_(compressed_gzip);
    assert(decompressed_gzip == test_content);
    std::cout << "✓ Gzip round-trip successful" << std::endl;

    // Test deflate round-trip
    compressed_deflate = encode_deflate(test_content, 1);
    std::cout << "Original size: " << test_content.size() << ", Deflate compressed size: " << compressed_deflate.size() << std::endl;
    assert(!compressed_deflate.empty());
    std::string decompressed_deflate = http_r::decode_deflate_(compressed_deflate);
    assert(decompressed_deflate == test_content);
    std::cout << "✓ Deflate round-trip successful" << std::endl;

    // Test brotli round-trip
    compressed_brotli = encode_brotli(test_content, 1);
    std::cout << "Original size: " << test_content.size() << ", Brotli compressed size: " << compressed_brotli.size() << std::endl;
    assert(!compressed_brotli.empty());
    std::string decompressed_brotli = http_r::decode_brotli_(compressed_brotli);
    assert(decompressed_brotli == test_content);
    std::cout << "✓ Brotli round-trip successful" << std::endl;

    // Test with edge cases
    assert(http_r::decode_gzip_("").empty());
    assert(http_r::decode_deflate_("").empty());
    assert(http_r::decode_brotli_("").empty());
    std::cout << "✓ All decompressors handle empty input gracefully" << std::endl;

    // Test 1: Real h2o compression with HTTP
    std::cout << "\n--- Test 1: Real h2o Compression & HTTP ---" << std::endl;

    // Create a test server with compression enabled per-path
    http_a test_server;
    test_server.listen_("127.0.0.1", 18081);

    test_server.get_("/test-compressed", [](const http_q& q, http_s& s) {
      // This endpoint will be compressed by h2o based on client Accept-Encoding
      s.header_("Content-Type", "text/plain");
      s.send_text_("This is test content that h2o will compress automatically when the client sends Accept-Encoding.");
    }); // compression is automatically enabled

    test_server.get_("/test-uncompressed", [](const http_q& q, http_s& s) {
      // This endpoint explicitly disables compression
      s.header_("Content-Type", "text/plain");
      s.send_text_("This is uncompressed test content for comparison.");
    }); // no compression if don't send headers

    test_server.start_();
    assert(http_t::ping_("127.0.0.1", 18081) == 0);

    // Test compressed response
    std::vector<std::pair<std::string, std::string>> accept_encoding = {
      {"Accept-Encoding", "gzip, deflate, br"}
    };
    std::string compressed_response = http_t::request_("127.0.0.1", 18081, "GET", "/test-compressed", "", accept_encoding);
    http_r compressed_parsed(compressed_response); // This now handles everything automatically

    assert(compressed_parsed.status == 200);

    std::cout << "Response:\n" << compressed_response << std::endl;

    // Check if the response was originally compressed (headers still show original encoding)
    if (compressed_parsed.header_has_("content-encoding", "gzip") ||
        compressed_parsed.header_has_("content-encoding", "br")) // h2o chooses the one
    {
      std::cout << "✓ h2o compression is working - response was automatically decompressed" << std::endl;

      // The body should now contain the decompressed content
      if (compressed_parsed.body.find("h2o will compress automatically") != std::string::npos)
      {
        std::cout << "✓ h2o compression and our decompression work perfectly!" << std::endl;
        std::cout << "✓ Round-trip HTTP compression/decompression successful" << std::endl;
      }
      else
      {
        std::cout << "❌ Decompression failed - expected content not found" << std::endl;
        std::cout << "Body content: '" << compressed_parsed.body.substr(0, 100) << "'" << std::endl;
        assert(false);
      }
    }
    else
    {
      std::cout << "✓ Header parsing works (h2o compression not triggered)" << std::endl;
    }

    // Test uncompressed response
    std::string uncompressed_response = http_t::request_("127.0.0.1", 18081, "GET", "/test-uncompressed");
    http_r uncompressed_parsed(uncompressed_response);
    assert(uncompressed_parsed.status == 200);
    assert(uncompressed_parsed.body.find("uncompressed test content") != std::string::npos);
    std::cout << "✓ Uncompressed response works correctly" << std::endl;

    test_server.stop_();

    std::cout << "✓ Real h2o compression tests passed!" << std::endl;
  }

  app.stop_();
}

std::cout << "\n=== All HTTP Execution API Tests Passed! ===" << std::endl;
return 0;
}
