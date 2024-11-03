#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 443
#define BUFFER_SIZE 4096
#define ALLOWED_DOMAIN "grabbiel.com"

// TODO: reduce logic
bool is_allowed_client(const struct sockaddr_in &client_addr,
                       const std::string &origin) {
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
  std::string ip_str = client_ip;

  bool ip_allowed = ALLOWED_IPS.find(ip_str) != ALLOWED_IPS.end();

  bool origin_allowed =
      origin.empty() || origin.find(ALLOWED_DOMAIN) != std::string::npos;

  printf("Connection attempt from IP: %s, Origin: %s\n", ip_str.c_str(),
         origin.empty() ? "direct acess" : origin.c_str());

  return ip_allowed || origin_allowed;
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

void handle_get_shop(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: pink; "
      "width: 90vw; height: 120vh;'>SHOP IS HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /shop\n");
}
void handle_get_donate(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: yellow; "
      "width: 90vw; height: 120vh;'>DONATIONS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /donate\n");
}
void handle_get_assets(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: blue; "
      "width: 90vw; height: 120vh;'>ASSETS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /assets\n");
}

void handle_get_forum(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: black; "
      "width: 90vw; height: 120vh;'>FORUM IS HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /forum\n");
}

void handle_get_updates(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: brown; "
      "width: 90vw; height: 120vh;'>UPDATES ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /updates\n");
}

void handle_get_me(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: grey; "
      "width: 90vw; height: 120vh;'>ME ITS ME IM HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /me\n");
}

void handle_get_photos(SSL *ssl, std::string &response) {
  response +=
      "<div id='text-space' class='content' style='background-color: green; "
      "width: 90vw; height: 120vh;'>PHOTOS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /photos\n");
}

void handle_get_links(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "light-blue; "
              "width: 90vw; height: 120vh;'>LINKS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /links\n");
}

void handle_get_news(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "orange; "
              "width: 90vw; height: 120vh;'>NEWS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /news\n");
}

void handle_get_videos(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "white; "
              "width: 90vw; height: 120vh;'>VIDEOS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /videos\n");
}

void handle_get_read(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "bisque; "
              "width: 90vw; height: 120vh;'>READ ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /read\n");
}

void handle_get_github(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "coral; "
              "width: 90vw; height: 120vh;'>GITHUB ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /github\n");
}

void handle_get_food(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "crimson; "
              "width: 90vw; height: 120vh;'>FOOD ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /food\n");
}

void handle_get_music(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "gainsboro; "
              "width: 90vw; height: 120vh;'>MUSIC ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /music\n");
}

void handle_get_renders(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "khaki; "
              "width: 90vw; height: 120vh;'>RENDERS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /renders\n");
}

void handle_get_writing(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "indigo; "
              "width: 90vw; height: 120vh;'>WRITING ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /writing\n");
}

void handle_get_vynils(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "lavender; "
              "width: 90vw; height: 120vh;'>VYNILS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /vynils\n");
}

void handle_get_travel(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "linen; "
              "width: 90vw; height: 120vh;'>TRAVEL ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /travel\n");
}

void handle_get_fishing(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "moccasin; "
              "width: 90vw; height: 120vh;'>FISHING ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /fishing\n");
}

void handle_get_scuba(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "orchid; "
              "width: 90vw; height: 120vh;'>SCUBA ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /scuba\n");
}

void handle_get_foreign(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "peru; "
              "width: 90vw; height: 120vh;'>FOREIGN ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /foreign\n");
}

void handle_get_leetcode(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "plum; "
              "width: 90vw; height: 120vh;'>LEETCODE ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /leetcode\n");
}

void handle_get_pretty(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "salmon; "
              "width: 90vw; height: 120vh;'>PRETTY ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /pretty\n");
}

void handle_get_robots(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "snow; "
              "width: 90vw; height: 120vh;'>ROBOTS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /robots\n");
}

void handle_get_stats(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "teal; "
              "width: 90vw; height: 120vh;'>STATS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /stats\n");
}

void handle_get_wishlist(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "thistle; "
              "width: 90vw; height: 120vh;'>WISHLIST ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /wishlist\n");
}

void handle_get_sections(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "tan; "
              "width: 90vw; height: 120vh;'>SECTIONS ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /sections\n");
}
void handle_get_anime(SSL *ssl, std::string &response) {
  response += "<div id='text-space' class='content' style='background-color: "
              "cornsilk; "
              "width: 90vw; height: 120vh;'>ANIME ARE HERE</div>";
  SSL_write(ssl, response.c_str(), response.length());
  printf("Processed POST request to /anime\n");
}

void handle_get(SSL *ssl, const std::string &req) {
  size_t path_start = req.find(" ") + 1;
  size_t path_end = req.find(" ", path_start);
  std::string path = req.substr(path_start, path_end - path_start);

  std::string response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: text/html\r\n";
  response += "Access-Control-Allow-Origin: https://";
  response += ALLOWED_DOMAIN;
  response += "\r\n";
  response += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
  response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
              "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";
  response += "Connection: close\r\n\r\n";

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
  }
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
    printf("Blocked unauthorized request from %s\n",
           inet_ntoa(client_addr.sin_addr));
    return;
  }

  printf("%s\n", request);

  if (req.find("OPTIONS") == 0) {
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Access-Control-Allow-Origin: https://";
    response += ALLOWED_DOMAIN;
    response += "\r\n";
    response += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    response += "Access-Control-Allow-Headers: Content-Type, X-Requested-With, "
                "HX-Request, HX-Trigger, HX-Target, HX-Current-URL\r\n";
    response += "Access-Control-Max-Age: 86400\r\n"; // 24 hours
    response += "Content-Length: 0\r\n";
    response += "\r\n";
    SSL_write(ssl, response.c_str(), response.length());
    return;
  }
  if (req.find("GET") == 0) {
    handle_get(ssl, req);
  } else {
    std::string response = "HTTP/1.1 404 Not Found\r\n";
    response += "Content-Type: text/plain\r\n";
    response += "Connection: close\r\n\r\n";
    response += "404 - Endpoint not found";
    SSL_write(ssl, response.c_str(), response.length());
    printf("Received non-matching request\n");
  }
}

int main(int argc, char const *argv[]) {

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = create_context();
  configure_context(ctx,
                    "/etc/letsencrypt/live/server.grabbiel.com/fullchain.pem",
                    "/etc/letsencrypt/live/server.grabbiel.com/privkey.pem");

  int server_fd, new_socket;
  ssize_t valread;
  struct sockaddr_in address;
  int opt = 1;
  socklen_t addrlen = sizeof(address);
  char buffer[BUFFER_SIZE] = {0};

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  // Set SO_REUSEPORT
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %d ... \n", PORT);

  while (1) {

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr,
                             &client_len)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    // ssl
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    } else {
      memset(buffer, 0, BUFFER_SIZE);
      int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

      if (bytes > 0) {
        buffer[bytes] = '\0';
        handle_request(ssl, buffer, client_addr);
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
  }
  SSL_CTX_free(ctx);
  close(server_fd);
  EVP_cleanup();

  return 0;
}
