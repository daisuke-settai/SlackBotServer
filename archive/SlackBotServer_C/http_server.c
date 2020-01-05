#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <wait.h>
#include <unistd.h>
#include "parson/parson.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define HTTPS_TCP_PORT	443
#define BUF_SIZE  1024
#define CRT_FILE "/etc/cert.pem" // dummy
#define KEY_FILE "/etc/privkey.pem"
#define FULLCHAIN_FILE "/etc/fullchain.pem"
#define IMCART_FILE "/etc/chain.pem"

#define errExit(msg) do {  \
  perror(msg);  \
  exit(EXIT_FAILURE); \
} while(0)

int sockfd = -1;

void httpd(SSL *ssl);
int send_msg(SSL *sl, char *msg);
void setup_sigchld();
void catch_SIGCHLD(int sig);
void setup_sigint();
void catch_SIGINT(int sig);
void get_response(SSL *ssl, char *data);
void post_response(SSL *ssl, char *data);
void process_jsondata(SSL *ssl, char *json_data);

int main()
{
  int accepted_fd;
  int client_addr_len;
  int err, sd;
  struct sockaddr_in server_addr, client_addr;
  SSL *ssl;
  SSL_CTX *ctx;

  setup_sigchld();

  // SSL setup
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
  // if ((ctx = SSL_CTX_new(TLSv1_server_method())) == NULL) {
    ERR_print_errors_fp(stderr);
    errExit("SSL_CTX_new");
  }
  // SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
  if (SSL_CTX_use_certificate_file(ctx, CRT_FILE, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    errExit("SSL_CTX_use_certificate_file");
  }
  if (SSL_CTX_use_certificate_chain_file(ctx, FULLCHAIN_FILE) != 1) {
    ERR_print_errors_fp(stderr);
    errExit("SSL_CTX_use_certificate_chain_file");
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != 1) {
    ERR_print_errors_fp(stderr);
    errExit("SSL_CTX_use_PrivateKey_file");
  }

  memset((char *)&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(HTTPS_TCP_PORT);

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    errExit("socket");

  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) < 0)
    errExit("setsockopt");

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    close(sockfd);
    errExit("bind");
  }

  if (listen(sockfd, 5) < 0) {
    close(sockfd);
    errExit("listen");
  }

  client_addr_len = sizeof(client_addr);
  while(1) {
    if ((accepted_fd = accept(sockfd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len)) < 0) {
      perror("accept");
      break;
    } else {
      printf("accepted\n"); fflush(stdout);


      if((ssl = SSL_new(ctx)) == NULL) {
        perror("SSL_new");
        ERR_print_errors_fp(stderr);
        close(accepted_fd);
        break;
      }
      printf("created new ssl\n"); fflush(stdout);
      if (SSL_set_fd(ssl, accepted_fd) == 0) {
        perror("SSL_set_fd");
        ERR_print_errors_fp(stderr);
        close(accepted_fd);
        SSL_free(ssl);
        break;
      }
      printf("ssl_set_fd\n"); fflush(stdout);

      if ((err = SSL_accept(ssl)) == 0) {
        perror("SSL_accept[0]");
        ERR_print_errors_fp(stderr);
        SSL_get_error(ssl, err);
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        continue;
      } else if (err < 0) {
        perror("SSL_accept[-](Client Hello is legacy version etc...)");
        ERR_print_errors_fp(stderr);
        SSL_get_error(ssl, err);
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        continue;
      }

      printf("ssl_accepted\n"); fflush(stdout);

      pid_t worker_pid = fork();
      if (worker_pid == -1) {
        perror("fork");
        break;
      } else if (worker_pid == 0) {
        close(sockfd);
        httpd(ssl);
        sd = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sd);
        exit(0);
      } else {
        close(accepted_fd);
      }
    }
  }
  close(sockfd);
  SSL_CTX_free(ctx);
  return 0;
}

void httpd(SSL *ssl)
{
  char buf[BUF_SIZE];
  char meth_name[16];
  char uri_addr[256];
  char http_ver[64];
  int len;
  if ((len = SSL_read(ssl, buf, BUF_SIZE)) < 0) {
    perror("read[-]:");
    ERR_print_errors_fp(stderr);
  } else if (len == 0) {
    perror("read[0]:");
    ERR_print_errors_fp(stderr);
  } else {
    printf("SSL_RECV: \n%s\n", buf);
    sscanf(buf, "%s %s %s", meth_name, uri_addr, http_ver);
    if (strncmp(meth_name, "GET", 3) == 0) {
      get_response(ssl, buf);
    } else if (strncmp(meth_name, "POST", 4) == 0) {
      post_response(ssl, buf);
    } else {
      send_msg(ssl, "501 Not Implemented\r\n");
    }
  }
}

int send_msg(SSL *ssl, char *msg) {
  int len;
  printf("\nSSL_SEND:\n\n%s\n", msg);
  len = strlen(msg);
  if (SSL_write(ssl, msg, len) != len) {
    perror("write");
    ERR_print_errors_fp(stderr);
  }
  return len;
}

void setup_sigchld()
{
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = catch_SIGCHLD;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_NOCLDSTOP | SA_RESTART;
  sigaction(SIGCHLD, &act, NULL);
}

void catch_SIGCHLD(int sig)
{
  pid_t child_pid = 0;
  do {
    int ret;
    child_pid = waitpid(-1, &ret, WNOHANG);
  } while(child_pid > 0);
}

void setup_sigint()
{
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = catch_SIGINT;
  sigemptyset(&act.sa_mask);
  sigaction(SIGINT, &act, NULL);
}

void catch_SIGINT(int sig)
{
  close(sockfd);
}

void get_response(SSL *ssl, char *data)
{
  char buf[BUF_SIZE];
  char *response_header =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: text/html\r\n"
    "Connection: Close\r\n"
    "\r\n"
    "%s";
  char *response_body =
    "GET request is not implemented\r\n<br>"
    "Not OK!!! :)\r\n";

  snprintf(buf, sizeof(buf), response_header, strlen(response_body), response_body);
  send_msg(ssl, buf);
  printf("SEND: \n%s\n", buf);
}

enum HttpHeader {
  HOST,
  USER_AGENT,
  ACCEPT,
  CONTENT_LENGTH,
  CONTENT_TYPE,
  HTTP_HEADER_NUM
};

// len: Bodyを除いたhttpリクエスト長
char *parse_header(char *header_buff[], char *data, int *len)
{
  char *index = data, *p;
  *len = 0;
  while(1){
    p = strstr(index, "\r\n");
    memset(p, 0, strlen("\r\n"));
    *len += strlen(index) + 2;
    if (strncmp(index, "\0", 1) == 0) {
      break;
    } else if (strncmp(index, "Host", 4) == 0) {
      header_buff[HOST] = index + 6;
    } else if (strncmp(index, "User-Agent", 10) == 0) {
      header_buff[USER_AGENT] = index + 12;
    } else if (strncmp(index, "Accept", 6) == 0) {
      header_buff[ACCEPT] = index + 8;
    } else if (strncmp(index, "Content-Length", 14) == 0) {
      header_buff[CONTENT_LENGTH] = index + 16;
    } else if (strncmp(index, "Content-Type", 12) == 0) {
      header_buff[CONTENT_TYPE] = index + 14;
    } else {
      fprintf(stderr, "http header parse error: %s\n", index);
    }
    index = p + 2;
  }
  return index + 2;
}

void dump_char_array(char *array[], int num)
{
  while (num) {
    printf("%s\n", array[HTTP_HEADER_NUM - num--]);
  }
}

void post_response(SSL *ssl, char *data)
{
  char *http_header[HTTP_HEADER_NUM];
  char *http_body;
  int header_len;
  char *buff;
  int content_len;
  http_body = parse_header(http_header, data, &header_len);
  // printf("\n<HTTP HEADER>\n\n");
  // dump_char_array(http_header, HTTP_HEADER_NUM);
  // printf("HTTP HEADER LEN: %d\n", header_len);
  content_len = atoi(http_header[CONTENT_LENGTH]);

  if(content_len > BUF_SIZE - header_len) {
    buff = (char *)malloc(content_len);
    strncpy(buff, http_body, strlen(http_body));
    int recv_len = strlen(http_body), len;
    char *index;
    index = buff + strlen(http_body);
    while(1) {
      if ((len = SSL_read(ssl, index, content_len - recv_len)) < 0) {
        ERR_print_errors_fp(stderr);
        int sd;
        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
        errExit("read loop");
      }
      recv_len += len;
      if (recv_len >= content_len)
        break;
    }
  } else {
    buff = http_body;
  }
  printf("\n<HTTP BODY>\n\n");
  printf("%s\n", buff);

  if (strncmp(http_header[CONTENT_TYPE], "application/json", 16) == 0) {
    process_jsondata(ssl, buff);
  } else if (strncmp(http_header[CONTENT_TYPE], "application/x-www-form-urlencoded", 33) == 0) {
    send_msg(ssl, "501 Not Implemented(POST applocation/x-www-form-urlencoded\r\n");
  } else {
    send_msg(ssl, "501 Not Implemented(POST)\r\n");
  }
}

// SlackBotAPI Event API
void process_jsondata(SSL *ssl, char *json_data){
  JSON_Value *root_value;
  JSON_Object *root_object;
  const char *type;
  char *buf;
  char msg[BUF_SIZE];

  printf("process_json\n"); fflush(stdout);
  root_value = json_parse_string(json_data);
  if(json_value_get_type(root_value) != JSONObject) {
    fprintf(stderr, "Error: json root_value type is not JSONObject\n");
    goto error;
  }
  root_object = json_value_get_object(root_value);
  type = json_object_get_string(root_object, "type");

  if(type == NULL)
    goto error;
  if(strncmp(type, "url_verification", 16) == 0) {
    // Challenge response
    buf =
      "HTTP 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Connection: Close\r\n"
      "\r\n"
      "%s\r\n";
    snprintf(msg, BUF_SIZE, buf, json_object_get_string(root_object, "challenge"));
    send_msg(ssl, msg);
  } else if (strncmp(type, "event_callback", 14) == 0) {
    send_msg(ssl, "200 そのうちやるよ\r\n");
  } else {
    send_msg(ssl, "501 I don't know such as json\r\n");
  }

  return;
error:
  send_msg(ssl, "501 Process JSONDATA(error)\r\n");
}
