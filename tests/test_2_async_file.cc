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

int main(int argc, char** argv)
{

// Test 0: Base64 encoding/decoding
std::cout << "\n=== Test 0: Base64 Encoding/Decoding ===" << std::endl;

{
  // Test 1: Empty data
  std::vector<uint8_t> empty_data;
  std::string encoded_empty = base64_encode_(empty_data);
  std::vector<uint8_t> decoded_empty = base64_decode_(encoded_empty);
  assert(encoded_empty.empty());
  assert(decoded_empty.empty());
  std::cout << "✓ Empty data encoding/decoding works" << std::endl;

  // Test 2: Simple binary data
  std::vector<uint8_t> test_data = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
  std::string encoded = base64_encode_(test_data);
  std::vector<uint8_t> decoded = base64_decode_(encoded);
  assert(decoded == test_data);
  std::cout << "✓ Binary data encoding/decoding works: '" << encoded << "'" << std::endl;

  // Test 3: Binary data with null bytes and special chars
  std::vector<uint8_t> binary_data = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 'A', 'B', 'C'};
  std::string encoded_binary = base64_encode_(binary_data);
  std::vector<uint8_t> decoded_binary = base64_decode_(encoded_binary);
  assert(decoded_binary == binary_data);
  std::cout << "✓ Complex binary data encoding/decoding works: '" << encoded_binary << "'" << std::endl;

  // Test 4: String data for header tokens
  std::string token_string = "Bearer my-secret-jwt-token-12345";
  std::vector<uint8_t> token_bytes(token_string.begin(), token_string.end());
  std::string encoded_token = base64_encode_(token_bytes);
  std::vector<uint8_t> decoded_token = base64_decode_(encoded_token);
  std::string decoded_string(decoded_token.begin(), decoded_token.end());
  assert(decoded_string == token_string);
  std::cout << "✓ Token string encoding/decoding works: '" << encoded_token << "'" << std::endl;

  // Test 5: Round-trip consistency
  for (int i = 0; i < 10; ++i) {
    std::vector<uint8_t> random_data;
    for (int j = 0; j < 100; ++j) {
      random_data.push_back(static_cast<uint8_t>(rand() % 256));
    }
    std::string encoded = base64_encode_(random_data);
    std::vector<uint8_t> decoded = base64_decode_(encoded);
    assert(decoded == random_data);
  }
  std::cout << "✓ Round-trip consistency test passed (10 iterations)\n" << std::endl;
}

std::cout << "=== Test: dat_ File Operations ===" << std::endl;

// Create test data
const char* test_data = "Hello, World! This is test data for file operations.";
[[maybe_unused]] const size_t test_data_len = strlen(test_data);
const char* append_data = " Appended content.";
[[maybe_unused]] const size_t append_data_len = strlen(append_data);

// Test 1: dat_new_ (save request body to new file)
{
  http_a app;
  app.listen_("127.0.0.1", 18099);

  app.post_("/test_new", [&](const http_q& q, http_s& s) {
    // Save request body to new file
    short result = q.dat_new_("test_file_new.txt");
    assert(result == 0);
    std::cout << "✓ dat_new_() saved request body to new file" << std::endl;

    s.send_text_("File created successfully");
  });

  app.start_();
  if (http_t::ping_("127.0.0.1", 18099) != 0)
  {
    std::cerr << "Failed to ping server" << std::endl;
    return 1;
  }

  // Send POST request with test data
  std::string response = http_t::request_("127.0.0.1", 18099, "POST", "/test_new", test_data);
  std::cout << response << std::endl;
  assert(http_t::response_is_(response, 200, "File created successfully"));

  // Verify file was created and contains correct data
  std::ifstream file("test_file_new.txt", std::ios::binary);
  assert(file.good());

  std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  assert(file_content == test_data);
  std::cout << "✓ File content matches request body" << std::endl;

  file.close();
  app.stop_();
}

// Test 2: dat_put_ (save request body to file, overwriting)
{
  http_a app;
  app.listen_("127.0.0.1", 18100);

  app.post_("/test_put", [&](const http_q& q, http_s& s) {
    // Save request body to file
    short result = q.dat_put_("test_file_put.txt");
    assert(result == 0);
    std::cout << "✓ dat_put_() saved request body to file" << std::endl;

    s.send_text_("Data saved successfully");
  });

  app.start_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Send POST request with test data
  std::string response = http_t::request_("127.0.0.1", 18100, "POST", "/test_put", test_data);
  assert(http_t::response_is_(response, 200, "Data saved successfully"));

  // Verify file content
  std::ifstream file("test_file_put.txt", std::ios::binary);
  std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  assert(file_content == test_data);
  std::cout << "✓ File content matches after dat_put_()" << std::endl;

  app.stop_();
}

// Test 3: dat_app_ (append request body to file)
{
  http_a app;
  app.listen_("127.0.0.1", 18101);

  app.post_("/test_app", [&](const http_q& q, http_s& s) {
    // Append request body to existing file
    short result = q.dat_app_("test_file_put.txt");
    assert(result == 0);
    std::cout << "✓ dat_app_() appended request body to file" << std::endl;

    s.send_text_("Data appended successfully");
  });

  app.start_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Send POST request with append data
  std::string response = http_t::request_("127.0.0.1", 18101, "POST", "/test_app", append_data);
  assert(http_t::response_is_(response, 200, "Data appended successfully"));

  // Verify appended content
  std::ifstream file("test_file_put.txt", std::ios::binary);
  std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  std::string expected = std::string(test_data) + append_data;
  assert(file_content == expected);
  std::cout << "✓ File content correct after dat_app_()" << std::endl;

  app.stop_();
}

// Test 4: dat_get_ (read from file) + send with http_b::O
{
  http_a app;
  app.listen_("127.0.0.1", 18102);

  app.get_("/test_get", [&](const http_q& q, http_s& s) {
    // Read file into h2o memory pool
    short result = s.dat_get_("test_file_put.txt");
    assert(result == 0);
    std::cout << "✓ dat_get_() read file into response" << std::endl;

    // Send data (already in h2o pool, so use http_b::O)
    s.send_(http_b::O);  // No copy needed, direct send
  });

  app.start_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Test the endpoint
  std::string response = http_t::request_("127.0.0.1", 18102, "GET", "/test_get");
  assert(http_t::response_is_(response, 200, std::string(test_data) + append_data));
  std::cout << "✓ dat_get_() + send_(http_b::O) works correctly" << std::endl;

  app.stop_();
}

// Test 5: dat_get_ with offset and bytes
{
  http_a app;
  app.listen_("127.0.0.1", 18103);

  app.get_("/test_partial", [&](const http_q& q, http_s& s) {
    // Read partial file (first 5 bytes)
    short result = s.dat_get_("test_file_put.txt", 0, 5);
    assert(result == 0);
    assert(s.data.b == 5);
    std::cout << "✓ dat_get_() with offset/bytes works" << std::endl;

    s.send_(http_b::O);
  });

  app.start_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  std::string response = http_t::request_("127.0.0.1", 18103, "GET", "/test_partial");
  assert(http_t::response_is_(response, 200, "Hello"));
  std::cout << "✓ Partial file read works correctly" << std::endl;

  app.stop_();
}

// Test 6: Advanced Authorization + Custom Filename via Headers
{
  std::cout << "\n=== Generating SSL Certificates ===" << std::endl;
  {
    // Check if certificates exist
    std::ifstream cert_file("httptest2v1.crt");
    std::ifstream key_file("httptest2v1.key");
    if (!cert_file.good() || !key_file.good())
    {
      std::cout << "Generating self-signed certificates..." << std::endl;

      // Generate private key and certificate using OpenSSL command
      int result =
          system("openssl req -x509 -newkey rsa:2048 -keyout httptest2v1.key "
                 "-out httptest2v1.crt -days 365 -nodes -subj "
                 "\"/C=US/ST=Test/L=Test/O=Test/CN=localhost\" 2>/dev/null");
      if (result != 0)
      {
        std::cerr << "Failed to generate SSL certificates. Please ensure OpenSSL is installed."
                  << std::endl;
        return 1;
      }
      std::cout
          << "✓ SSL certificates generated: httptest2v1.crt, httptest2v1.key"
          << std::endl;
    }
    else std::cout << "✓ SSL certificates already exist" << std::endl;
  }
  std::cout << "\n=== Setting up SSL HTTP Server ===" << std::endl;

  http_a app;
  app.ssl_("httptest2v1.crt", "httptest2v1.key");

  app.listen_("127.0.0.1", 18104);

  app.post_("/secure_upload", [&](const http_q& q, http_s& s) {
    // Check authorization header
    std::string auth_header = q.header_("authorization");
    if (auth_header != "Bearer secret-token-123") {
      s.status_(401);
      s.send_text_("Unauthorized: Invalid or missing authorization token");
      return;
    }

    // Get custom filename from header
    std::string custom_filename = q.header_("x-filename");
    if (custom_filename.empty()) {
      s.status_(400);
      s.send_text_("Bad Request: X-Filename header required");
      return;
    }

    // Validate filename (basic security check)
    if (custom_filename.find("..") != std::string::npos ||
        custom_filename.find("/") != std::string::npos) {
      s.status_(403);
      s.send_text_("Forbidden: Invalid filename");
      return;
    }

    // Save request body to custom filename
    short result = q.dat_new_(custom_filename);
    if (result != 0) {
      s.status_(500);
      s.send_text_("Internal Server Error: Failed to save file");
      return;
    }

    s.status_(201);
    s.send_text_("File uploaded successfully to: " + custom_filename);
  });

  app.start_();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // Test 1: Unauthorized request (no auth header)
  std::cout << "\n--- Testing Authorization ---" << std::endl;
  std::string response1 = http_t::request_("127.0.0.1", 18104, "POST", "/secure_upload", "test data", {}, 0, true);
  assert(http_t::response_is_(response1, 401, "Unauthorized: Invalid or missing authorization token"));
  std::cout << "✓ Unauthorized request properly rejected" << std::endl;

  // Test 2: Unauthorized request (wrong token)
  std::vector<std::pair<std::string, std::string>> wrong_auth_headers = {
    {"Authorization", "Bearer wrong-token"}
  };
  std::string response2 = http_t::request_("127.0.0.1", 18104, "POST", "/secure_upload", "test data", wrong_auth_headers, 0, true);
  assert(http_t::response_is_(response2, 401, "Unauthorized: Invalid or missing authorization token"));
  std::cout << "✓ Wrong token properly rejected" << std::endl;

  // Test 3: Authorized request but missing filename
  std::vector<std::pair<std::string, std::string>> auth_headers = {
    {"Authorization", "Bearer secret-token-123"}
  };
  std::string response3 = http_t::request_("127.0.0.1", 18104, "POST", "/secure_upload", "test data", auth_headers, 0, true);
  assert(http_t::response_is_(response3, 400, "Bad Request: X-Filename header required"));
  std::cout << "✓ Missing filename header properly rejected" << std::endl;

  // Test 4: Authorized request with invalid filename (path traversal attempt)
  std::vector<std::pair<std::string, std::string>> bad_filename_headers = {
    {"Authorization", "Bearer secret-token-123"},
    {"X-Filename", "../../../etc/passwd"}
  };
  std::string response4 = http_t::request_("127.0.0.1", 18104, "POST", "/secure_upload", "test data", bad_filename_headers, 0, true);
  assert(http_t::response_is_(response4, 403, "Forbidden: Invalid filename"));
  std::cout << "✓ Path traversal attempt properly blocked" << std::endl;

  // Test 5: Authorized request with valid filename
  std::vector<std::pair<std::string, std::string>> valid_headers = {
    {"Authorization", "Bearer secret-token-123"},
    {"X-Filename", "secure_upload_test.txt"}
  };
  std::string response5 = http_t::request_("127.0.0.1", 18104, "POST", "/secure_upload", "secure file content", valid_headers, 0, true);
  assert(http_t::response_is_(response5, 201, "File uploaded successfully to: secure_upload_test.txt"));
  std::cout << "✓ Authorized upload with custom filename successful" << std::endl;

  // Verify file was created with correct content
  std::ifstream secure_file("secure_upload_test.txt", std::ios::binary);
  assert(secure_file.good());
  std::string file_content((std::istreambuf_iterator<char>(secure_file)), std::istreambuf_iterator<char>());
  assert(file_content == "secure file content");
  secure_file.close();
  std::cout << "✓ Secure file content verified" << std::endl;

  app.stop_();
}

// Cleanup
std::filesystem::remove("test_file_new.txt");
std::filesystem::remove("test_file_put.txt");
std::filesystem::remove("secure_upload_test.txt");
std::filesystem::remove("httptest2v1.crt");
std::filesystem::remove("httptest2v1.key");

std::cout << "\n=== All dat_ Operation Tests Passed! ===" << std::endl;
return 0;
}
