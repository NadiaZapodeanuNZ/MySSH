#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 2607
#define MAX_BUFFER 2048
#define SERVER_IP "127.0.0.1" 

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}


SSL_CTX *create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("ERROR: Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //  the SSL context to verify the server's certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //  the client accepts only strong TLS versions
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
}


int main() {
    printf("----------------------WELCOME TO MYSSH-------------------------------------------------\n");
    printf("----------HERE YOU CAN SEND COMMANDS TO THE SERVER-------------------------------------\n");
    printf("-----All you have to do is to login with your username and password to------------------\n");
    printf("be able to send commands. if you are not registered,you can register--------------------\n");
    printf("using the command \"register: username@MySSH password:password\".and then login to the--\n");
    printf("server with the command \"login: username@MySSH password:password\".--------------------\n");
    printf(".Then you can login to the server-------------------------------------------------------\n");
    printf("The commands you can use are the following:---------------------------------------------\n");
    printf("-----------1.login----------------------------------------------------------------------\n");
    printf("-----------2.register-------------------------------------------------------------------\n");
    printf("-----------3.download file from server--------------------------------------------------\n");
    printf("-----------4.upload file to server------------------------------------------------------\n");
    printf("-----------5.quit-----------------------------------------------------------------------\n");
    printf("-----------6.all multiple commands from path (bash)-------------------------------------\n");
    printf("---WHAT ARE YOU WAITING FOR?------------------------------------------------------------\n");
    printf("---Sign up and login! :))) -------------------------------------------------------------\n");
    printf ("\n");
    printf ("\n");
    printf ("\n");
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    char buffer[MAX_BUFFER];

    initialize_openssl();

    // Creare context SSL
    ctx = create_context();
    configure_context(ctx);

    // Creare socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server address");
        exit(EXIT_FAILURE);
    }

    // Conectare la server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Creare obiect SSL și legarea la socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Handshake SSL
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("SSL handshake done\n");
   while (1) 
   {
    printf("Enter command:");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("DEBUG: Sending command: '%s'\n", buffer);  // Debug
    SSL_write(ssl, buffer, strlen(buffer));
  
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) 
    {
        buffer[bytes] = '\0';
        printf("Server response: %s\n", buffer);
        if (strncmp(buffer, "quit", 4) == 0) 
        {
        printf("Client shutting down...\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        exit(0);
        }
    } else {
        printf("ERROR: No response from server\n");
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}

