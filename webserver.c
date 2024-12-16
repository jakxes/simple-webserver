#include <ctype.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

#define MAX_BUFFER_SIZE 8192
#define MAX_DYNAMIC_RESOURCES 100

typedef struct Node {
    char *key;
    char *value;
    struct Node *next;
} Node;

Node *head = NULL;

void set_content(const char *key, const char *value) {
    Node *current = head;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            free(current->value);
            current->value = strdup(value);
            return;
        }
        current = current->next;
    }

    Node *new_node = malloc(sizeof(Node));
    new_node->key = strdup(key);
    new_node->value = strdup(value);
    new_node->next = head;
    head = new_node;
}
char *get_content(const char *key) {
    Node *current = head;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            return current->value;
        }
        current = current->next;
    }
    return NULL;
}
void remove_content(const char *key) {
    Node *current = head, *prev = NULL;
    while (current != NULL) {
        if (strcmp(current->key, key) == 0) {
            if (prev == NULL) {
                head = current->next;
            } else {
                prev->next = current->next;
            }
            free(current->key);
            free(current->value);
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}
static struct sockaddr_in derive_sockaddr(const char* host, const char* port) {
    struct addrinfo hints = {
        .ai_family = AF_INET, // Use IPv4
    };
    struct addrinfo *result_info;

    int return_code = getaddrinfo(host, port, &hints, &result_info);
    if (return_code != 0) {
        fprintf(stderr, "Error parsing host/port: %s\n", gai_strerror(return_code));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in result = *((struct sockaddr_in*) result_info->ai_addr);
    freeaddrinfo(result_info);

    return result;
}
void send_response(int client_fd, int status_code, const char *status_text, const char *content) {
    char response[MAX_BUFFER_SIZE];
    int content_length = content ? strlen(content) : 0;
    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Length: %d\r\n"
             "\r\n%s",
             status_code, status_text, content_length, content ? content : "");
    send(client_fd, response, strlen(response), 0);
}
int validate_header(char *line) {
    char *colon_pos = strchr(line, ": ");
    if (!colon_pos) return 0;
    size_t key_len = colon_pos - line;
    char *value = colon_pos + 1;
    while (*value == ' ') value++;
    return (key_len > 0 && *value != '\0');
}
void process_headers(char *headers_start, int client_fd) {
    char *headers_end = strstr(headers_start, "\r\n\r\n");
    if (!headers_end) {
        send_response(client_fd, 400, "Bad Request", NULL);
        return;
    }
    *headers_end = '\0';


    char *line = strtok(headers_start, "\r\n");
    while (line) {
        if (strlen(line) > 0 && !validate_header(line)) {
            send_response(client_fd, 400, "Bad Request", NULL);
            return;
        }
        line = strtok(NULL, "\r\n");
    }
}
void handle_http_request(int client_fd) {
    char buffer[MAX_BUFFER_SIZE];
    size_t total_received = 0;

    while (1) {
        ssize_t bytes_received = recv(client_fd, buffer + total_received, sizeof(buffer) - total_received - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received < 0) perror("Error receiving data");
            break;
        }
        total_received += bytes_received;
        char *request_end = strstr(buffer, "\r\n\r\n");
        if (request_end == NULL) continue;
        *request_end = '\0';
        request_end += 4;

        char method[16], uri[256], version[16];
        if (sscanf(buffer, "%15s %255s %15s", method, uri, version) != 3 || strncmp(version, "HTTP/", 5) != 0) {
            send_response(client_fd, 400, "Bad Request", NULL);
            close(client_fd);
            return;
        }

        printf("\n\n\"%s\"\n\n", buffer);

        if (strcmp(method, "GET") == 0) {
            if (strncmp(uri, "/static/", 8) == 0) {
                const char *resource = uri + 8;
                if (strcmp(resource, "foo") == 0) send_response(client_fd, 200, "OK", "Foo");
                else if (strcmp(resource, "bar") == 0) send_response(client_fd, 200, "OK", "Bar");
                else if (strcmp(resource, "baz") == 0) send_response(client_fd, 200, "OK", "Baz");
                else send_response(client_fd, 404, "Not Found", NULL);

            } else if (strncmp(uri, "/dynamic/", 9) == 0) {
                char *content = get_content(uri);
                if (content) send_response(client_fd, 200, "OK", content);
                else send_response(client_fd, 404, "Not Found", NULL);

            } else send_response(client_fd, 404, "Not Found", NULL);

        } else if (strcmp(method, "PUT") == 0) {
            if (strncmp(uri, "/dynamic/", 9) == 0) {
                if(get_content(uri)) {
                    set_content(uri, request_end);
                    send_response(client_fd, 204, "No Content", NULL);
                } else {
                    set_content(uri, request_end);
                    send_response(client_fd, 201, "Created", NULL);
                }

            } else send_response(client_fd, 403, "Forbidden", NULL);

        } else if (strcmp(method, "DELETE") == 0) {
            if (strncmp(uri, "/dynamic/", 9) == 0) {
                if (get_content(uri)) {
                    remove_content(uri);
                    send_response(client_fd, 204, "No Content", NULL);
                } else send_response(client_fd, 404, "Not Found", NULL);

            } else send_response(client_fd, 403, "Forbidden", NULL);

        } else send_response(client_fd, 501, "Not Implemented", NULL);

        size_t remaining = total_received - (request_end - buffer);
        memcpy(buffer, request_end, remaining);
        total_received = remaining;
    }
    close(client_fd);
}
void start_server(int server_fd) {
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }
        handle_http_request(client_fd);
    }
}
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr = derive_sockaddr(argv[1], argv[2]);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        return EXIT_FAILURE;
    }

    start_server(server_fd);
    return EXIT_SUCCESS;
}
