#include "../include/http_a_server.hh"

#include <cassert>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <chrono>
#include <thread>
#include <string>

int main(int argc, char** argv)
{

std::cout << "=== SSL HTTP Server Test for curl ===" << std::endl;
std::cout << "Testing SSL-enabled HTTP server with curl compatibility" << std::endl;

// Create SSL certificates for testing (if not exists)
std::cout << "\n=== Generating SSL Certificates ===" << std::endl;
{
  // Check if certificates exist
  std::ifstream cert_file("httptest1v1.crt");
  std::ifstream key_file("httptest1v1.key");

  if (!cert_file.good() || !key_file.good()) {
    std::cout << "Generating self-signed certificates..." << std::endl;

    // Generate private key and certificate using OpenSSL command
    int result = system("openssl req -x509 -newkey rsa:2048 -keyout httptest1v1.key -out httptest1v1.crt -days 365 -nodes -subj \"/C=US/ST=Test/L=Test/O=Test/CN=localhost\" 2>/dev/null");

    if (result != 0) {
      std::cerr << "Failed to generate SSL certificates. Please ensure OpenSSL is installed." << std::endl;
      return 1;
    }

    std::cout << "✓ SSL certificates generated: httptest1v1.crt, httptest1v1.key" << std::endl;
  } else {
    std::cout << "✓ SSL certificates already exist" << std::endl;
  }
}

std::cout << "\n=== Setting up SSL HTTP Server ===" << std::endl;
http_a app;

// Setup SSL with the generated certificates
try {
  app.ssl_("httptest1v1.crt", "httptest1v1.key");
  std::cout << "✓ SSL context configured" << std::endl;
} catch (const std::exception& e) {
  std::cerr << "✗ SSL setup failed: " << e.what() << std::endl;
  return 1;
}

// Setup listener on port 18443
try {
  app.listen_("127.0.0.1", 18443);
  std::cout << "✓ HTTPS listener configured on port 18443" << std::endl;
} catch (const std::exception& e) {
  std::cerr << "✗ Listener setup failed: " << e.what() << std::endl;
  return 1;
}

// Register some test routes
app.get_("/hello", [](const http_q& q, http_s& s) {
  s.status_(200);
  s.send_text_("Hello from SSL HTTP Server! Method: GET, URL: " + std::string(q.url) + "\n");
});

app.get_("/health", [](const http_q& q, http_s& s) {
  s.status_(200);
  s.send_text_("Server is healthy - SSL enabled, uptime available via app.uptime_()\n");
});

app.post_("/echo", [](const http_q& q, http_s& s) {
  s.status_(200);
  s.send_text_("Echo: Received POST to " + std::string(q.url_rest) + " with query: " + std::string(q.url_query) + "\n");
});

app.get_("/json", [](const http_q& q, http_s& s) {
  s.status_(200);
  s.send_json_(std::string("{\"message\":\"Hello from SSL server\",\"method\":\"GET\",\"path\":\"") + std::string(q.url) + "\"}\n");
});

std::cout << "✓ Routes registered:" << std::endl;
std::cout << "  GET  /hello     - Basic hello response (text)" << std::endl;
std::cout << "  GET  /health    - Health check (text)" << std::endl;
std::cout << "  POST /echo      - Echo request info (text)" << std::endl;
std::cout << "  GET  /json      - JSON response" << std::endl;

// Setup signal handling for graceful shutdown
app.signal_();
std::cout << "✓ Signal handling configured (Ctrl+C to stop)" << std::endl;

// Start the server
std::cout << "\n=== Starting SSL HTTP Server ===" << std::endl;
app.start_();

std::cout << "✓ Server started successfully!" << std::endl;
std::cout << "✓ Listening on https://127.0.0.1:18443/" << std::endl;

// Wait for server to be ready
std::this_thread::sleep_for(std::chrono::milliseconds(500));

std::cout << "\n=== Ready for curl testing! ===" << std::endl;
std::cout << "Try these curl commands:" << std::endl;
std::cout << "" << std::endl;
std::cout << "# Basic HTTPS request (skip cert verification):" << std::endl;
std::cout << "curl -k https://127.0.0.1:18443/hello" << std::endl;
std::cout << "" << std::endl;
std::cout << "# Health check:" << std::endl;
std::cout << "curl -k https://127.0.0.1:18443/health" << std::endl;
std::cout << "" << std::endl;
std::cout << "# POST request:" << std::endl;
std::cout << "curl -k -X POST https://127.0.0.1:18443/echo/m100?key=value" << std::endl;
std::cout << "" << std::endl;
std::cout << "# JSON response:" << std::endl;
std::cout << "curl -k https://127.0.0.1:18443/json" << std::endl;
std::cout << "" << std::endl;
std::cout << "# Test with verbose output:" << std::endl;
std::cout << "curl -k -v https://127.0.0.1:18443/hello" << std::endl;
std::cout << "" << std::endl;

// Keep server running until interrupted
std::cout << "Server is running... Press Ctrl+C to stop and exit." << std::endl;
std::cout << "==========================================================" << std::endl;

// Wait indefinitely (signal handler will stop the server)
while (app.state.load() == 2) { // serving
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
// or just app.serve_()

std::cout << "\n✓ Server stopped gracefully" << std::endl;

// Clean up SSL certificates
std::cout << "\n=== Cleaning up SSL certificates ===" << std::endl;
std::remove("httptest1v1.crt");
std::remove("httptest1v1.key");
std::cout << "✓ SSL certificates removed" << std::endl;

std::cout << "✓ Test completed successfully" << std::endl;

return 0;

}
