#include "include/Logger.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <set>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define ALLOWED_DOMAIN "grabbiel.com"

namespace fs = std::filesystem;

bool is_allowed_client(const struct sockaddr_in &client_addr,
                       const std::string &origin) {
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
  std::string ip_str = client_ip;

  bool origin_allowed =
      origin.empty() || origin.find(ALLOWED_DOMAIN) != std::string::npos;

  LOG_INFO("Connection attempt from IP: ", ip_str,
           ", Origin: ", origin.empty() ? "direct access" : origin);

  return origin_allowed;
}

std::string get_origin_header(const std::string &request) {
  std::string origin;
  size_t pos = request.find("Origin: ");
  if (pos != std::string::npos) {
    size_t end = request.find("\r\n", pos);
    origin = request.substr(pos + 8, end - (pos + 8));
  }
  return origin;
}

SSL_CTX *create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

void configure_context(SSL_CTX *ctx, const char *cert_path,
                       const char *key_path) {
  if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

bool ends_with(const std::string &str, const std::string &suffix) {
  return str.size() >= suffix.size() &&
         str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

void handle_get_article_file(SSL *ssl, std::string &response,
                             const std::string &path) {
  // Expected path: /article/15/index.html
  std::string article_prefix = "/article/";
  std::string storage_root = "/var/lib/article-content/";

  std::string subpath =
      path.substr(article_prefix.length()); // e.g., "15/index.html"
  size_t slash_pos = subpath.find('/');
  if (slash_pos == std::string::npos) {
    LOG_WARNING("Invalid article file path: ", path);
    response = "HTTP/1.1 400 Bad Request\r\n\r\n";
    SSL_write(ssl, response.c_str(), response.length());
    return;
  }

  std::string article_id = subpath.substr(0, slash_pos); // "15"
  std::string file_path = subpath.substr(slash_pos + 1); // "index.html"
  std::string full_path = storage_root + article_id + "/" + file_path;

  std::ifstream file(full_path, std::ios::binary);
  if (!file.is_open()) {
    LOG_WARNING("Article file not found: ", full_path);
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
    SSL_write(ssl, response.c_str(), response.length());
    return;
  }

  std::ostringstream buffer;
  buffer << file.rdbuf();
  std::string body = buffer.str();

  // Infer content type
  std::string content_type = "text/plain";
  if (ends_with(file_path, ".html")) {
    content_type = "text/html";
  } else if (ends_with(file_path, ".css")) {
    content_type = "text/css";
  } else if (ends_with(file_path, ".js")) {
    content_type = "application/javascript";
  }

  response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: " + content_type + "\r\n";
  response += "Access-Control-Allow-Origin: https://";
  response += ALLOWED_DOMAIN;
  response += "\r\n";
  response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
  response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
              "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";
  response += "Content-Length: " + std::to_string(body.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += body;

  SSL_write(ssl, response.c_str(), response.length());
}

void handle_get_shop(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>SHOP IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}
void handle_get_donate(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>DONATIONS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}
void handle_get_assets(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>ASSETS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_forum(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>FORUM IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_updates(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>UPDATES ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_me(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>ME IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_photos(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>PHOTOS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_links(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>LINKS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_news(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>NEWS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_videos(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>VIDEOS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_read(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>READ IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_github(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>GITHUB IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_food(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>FOOD IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_music(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>MUSIC IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_renders(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>RENDERS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_writing(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>WRITING IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_vynils(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>VINYLS IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_travel(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>TRAVEL IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_fishing(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>FISHING IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_scuba(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>SCUBA IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_foreign(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>FOREIGN IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_leetcode(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>LEETCODE IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_pretty(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>PRETTY IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_robots(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>ROBOTS IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_stats(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>STATS IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_wishlist(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>WISHLIST IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get_sections(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>SECTIONS ARE HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}
void handle_get_anime(SSL *ssl, std::string &response) {
  std::string content = "";
  content =
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>ANIME IS HERE</div>";
  response += "Content-Length: " + std::to_string(content.length()) + "\r\n";
  response += "Connection: close\r\n\r\n";
  response += content;
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}

void handle_get(SSL *ssl, const std::string &req) {
  size_t path_start = req.find(" ") + 1;
  size_t path_end = req.find(" ", path_start);
  std::string path = req.substr(path_start, path_end - path_start);

  LOG_INFO("Processing GET request for path: ", path);

  std::string response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: text/html\r\n";
  response += "Access-Control-Allow-Origin: https://";
  response += ALLOWED_DOMAIN;
  response += "\r\n";
  response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
  response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
              "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";

  if (path == "/shop") {
    handle_get_shop(ssl, response);
  } else if (path == "/donate") {
    handle_get_donate(ssl, response);
  } else if (path == "/assets") {
    handle_get_assets(ssl, response);
  } else if (path == "/forum") {
    handle_get_forum(ssl, response);
  } else if (path == "/updates") {
    handle_get_updates(ssl, response);
  } else if (path == "/me") {
    handle_get_me(ssl, response);
  } else if (path == "/news") {
    handle_get_news(ssl, response);
  } else if (path == "/wishlist") {
    handle_get_wishlist(ssl, response);
  } else if (path == "/stats") {
    handle_get_stats(ssl, response);
  } else if (path == "/videos") {
    handle_get_videos(ssl, response);
  } else if (path == "/write") {
    handle_get_writing(ssl, response);
  } else if (path == "/leetcode") {
    handle_get_leetcode(ssl, response);
  } else if (path == "/links") {
    handle_get_links(ssl, response);
  } else if (path == "/sections") {
    handle_get_sections(ssl, response);
  } else if (path == "/read") {
    handle_get_read(ssl, response);
  } else if (path == "/food") {
    handle_get_food(ssl, response);
  } else if (path == "/music") {
    handle_get_music(ssl, response);
  } else if (path == "/anime") {
    handle_get_anime(ssl, response);
  } else if (path == "/renders") {
    handle_get_renders(ssl, response);
  } else if (path == "/writing") {
    handle_get_writing(ssl, response);
  } else if (path == "/vynils") {
    handle_get_vynils(ssl, response);
  } else if (path == "/travel") {
    handle_get_travel(ssl, response);
  } else if (path == "/foreign") {
    handle_get_foreign(ssl, response);
  } else if (path == "/robots") {
    handle_get_robots(ssl, response);
  } else if (path == "/stats") {
    handle_get_stats(ssl, response);
  } else if (path == "/photos") {
    handle_get_photos(ssl, response);
  } else if (path == "/github") {
    handle_get_github(ssl, response);
  } else if (path == "/fishing") {
    handle_get_fishing(ssl, response);
  } else if (path == "/pretty") {
    handle_get_pretty(ssl, response);
  } else if (path == "/scuba") {
    handle_get_scuba(ssl, response);
  } else if (path.rfind("/article/", 0) == 0) {
    if (std::count(path.begin(), path.end(), '/') == 2 &&
        !ends_with(path, "/")) {
      handle_get_article_file(ssl, response, path + "/index.html");
    } else {
      handle_get_article_file(ssl, response, path);
    }
  } else {
    std::string not_found = "HTTP/1.1 404 Not Found\r\nContent-Type: "
                            "text/plain\r\n\r\n404 - Not Found";
    SSL_write(ssl, not_found.c_str(), not_found.length());
    LOG_WARNING("Unhandled GET path: ", path);
  }
  LOG_INFO("Sent response for path: ", path, ", length: ", response.length());
}

void handle_request(SSL *ssl, const char *request,
                    const struct sockaddr_in &client_addr) {

  std::string req(request);
  std::string origin = get_origin_header(req);

  if (!is_allowed_client(client_addr, origin)) {
    std::string response = "HTTP/1.1 403 Forbidden\r\n";
    response += "Content-Type: text/plain\r\n";
    response += "Connection: close\r\n\r\n";
    response += "Access denied: Unauthorized origin or IP address";
    SSL_write(ssl, response.c_str(), response.length());
    LOG_WARNING("Blocked unauthorized request from ",
                inet_ntoa(client_addr.sin_addr));
    return;
  }

  LOG_DEBUG("Received request: ", request);

  if (req.find("OPTIONS") == 0) {
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Access-Control-Allow-Origin: https://";
    response += ALLOWED_DOMAIN;
    response += "\r\n";
    response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
                "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";
    response += "Access-Control-Max-Age: 86400\r\n"; // 24 hours
    response += "Content-Length: 0\r\n";
    response += "Connection: keep-alive\r\n";
    response += "\r\n";
    SSL_write(ssl, response.c_str(), response.length());
    LOG_INFO("Responded to OPTIONS request with CORS headers");
    return;
  }
  if (req.find("GET") == 0) {
    handle_get(ssl, req);
  } else {
    std::string response = "HTTP/1.1 404 Not Found\r\n";
    response += "Content-Type: text/plain\r\n";
    response += "Access-Control-Allow-Origin: https://grabbiel.com\r\n";
    response += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
                "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";
    response += "Connection: close\r\n\r\n";
    response += "404 - Endpoint not found";
    SSL_write(ssl, response.c_str(), response.length());
    LOG_WARNING("Received non-matching request method");
  }
}

int main(int argc, char const *argv[]) {
  // Initialize logger
  Logger::getInstance().setLogFile("/var/log/grabbiel-server.log");
  Logger::getInstance().setLogLevel(LogLevel::INFO);

  LOG_INFO("Server starting initialization...");

  // Get port from environment or use default
  int port = 8444; // Default port
  const char *env_port = getenv("PORT");
  if (env_port != nullptr) {
    port = atoi(env_port);
    if (port <= 0) {
      LOG_ERROR("Invalid PORT value: ", env_port, ", using default 8444");
      port = 8444;
    }
  }
  LOG_INFO("Using port: ", port);

  // Print current process ID for debugging
  LOG_INFO("Process ID: ", getpid());

  // Initialize OpenSSL
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = create_context();
  configure_context(ctx,
                    "/etc/letsencrypt/live/server.grabbiel.com/fullchain.pem",
                    "/etc/letsencrypt/live/server.grabbiel.com/privkey.pem");

  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  socklen_t addrlen = sizeof(address);
  char buffer[BUFFER_SIZE] = {0};

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_FATAL("Socket creation failed: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    LOG_ERROR("Failed to set SO_REUSEADDR: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Set SO_REUSEPORT
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
    LOG_ERROR("Failed to set SO_REUSEPORT: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  // Attempt to bind with better error logging
  int bind_result =
      bind(server_fd, (struct sockaddr *)&address, sizeof(address));
  if (bind_result < 0) {
    LOG_FATAL("Bind failed: ", strerror(errno));

    // Additional debugging
    LOG_ERROR("Port in use check:");
    system("ss -tulpn | grep 8444 >> /var/log/grabbiel-server.log");

    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 10) < 0) {
    LOG_FATAL("Listen failed: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  LOG_INFO("Server listening on port ", port);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr,
                             &client_len)) < 0) {
      LOG_ERROR("Accept failed: ", strerror(errno));
      continue; // Continue instead of exiting to keep server running
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);

    if (SSL_accept(ssl) <= 0) {
      LOG_ERROR("SSL accept failed");
      ERR_print_errors_fp(stderr);
    } else {
      memset(buffer, 0, BUFFER_SIZE);
      int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

      if (bytes > 0) {
        buffer[bytes] = '\0';
        handle_request(ssl, buffer, client_addr);
      } else {
        LOG_ERROR("SSL_read failed: ", SSL_get_error(ssl, bytes));
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
  }

  LOG_INFO("Server shutting down...");
  SSL_CTX_free(ctx);
  close(server_fd);
  EVP_cleanup();

  return 0;
}
