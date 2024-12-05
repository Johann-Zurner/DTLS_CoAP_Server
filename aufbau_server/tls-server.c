#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#define BASE_PATH               "/root/wolfssl/bin/server/"
#define SERVER_PORT             2444
#define BUFFER_SIZE             4096
#define SERVER_KEY              BASE_PATH "certs/serverCert/key/server-key1.pem"
#define SERVER_CERT             BASE_PATH "certs/serverCert/cert/server-cert1.pem"
#define ROOT_CA_DIRECTORY       BASE_PATH "certs/rootCAs/rootCerts"

int main()
{
    int                         sockfd, clientfd;
    struct sockaddr_in          servAddr, clientAddr;
    socklen_t                   clientAddrLen;
    char                        buffer[BUFFER_SIZE];
    int                         ret;
    WOLFSSL_CTX*                ctx;
    WOLFSSL*                    ssl;
    WOLFSSL_METHOD*             method = wolfTLSv1_2_server_method();

    // Create a TCP socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Set up the server address struct
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERVER_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the address and port
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }

    // Listen for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("Listen failed");
        close(sockfd);
        return -1;
    }

    // Initialize WolfSSL library
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    // Create a new WolfSSL context
    ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        printf("Failed to create WOLFSSL_CTX\n");
        close(sockfd);
        return -1;
    }

    // Load CA certificates
    ret = wolfSSL_CTX_load_verify_locations(ctx, NULL, ROOT_CA_DIRECTORY);
    if (ret == WOLFSSL_SUCCESS) {
        printf("\033[32mCA-cert load success\033[0m\n");
    } else {
        printf("\033[31mCA-cert fail. Error: %d\033[0m\n", ret);
        printf("\033[31mError message: %s\033[0m\n", wolfSSL_ERR_reason_error_string(ret));
    }

    // Load server certificate
    ret = wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS) {
        printf("\033[32mServer-cert load success\033[0m\n");
    } else {
        printf("\033[31mServer-cert fail. Error: %d\033[0m\n", ret);
    }

    // Load server private key
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS) {
        printf("\033[32mKey load success\033[0m\n");
    } else {
        printf("\033[31mKey fail. Error: %d\033[0m\n", ret);
    }

    // Set verification mode
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    // Wait for a client connection
    clientAddrLen = sizeof(clientAddr);
    printf("Server is listening on port %d...\n", SERVER_PORT);
    clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (clientfd < 0) {
        perror("Accept failed");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return -1;
    }

    // Create a new WolfSSL object
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        printf("Failed to create WOLFSSL object\n");
        wolfSSL_CTX_free(ctx);
        close(clientfd);
        close(sockfd);
        return -1;
    }

    // Associate the client socket with the WolfSSL session
    wolfSSL_set_fd(ssl, clientfd);

    // Perform the TLS handshake
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        printf("wolfSSL Error: %d\n", wolfSSL_get_error(ssl, -1));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        close(clientfd);
        close(sockfd);
        return -1;
    }

    // Receive data from the client
    ret = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (ret > 0) {
        buffer[ret] = '\0'; // Null-terminate the received string
        printf("Received: %s\n", buffer);
    }

    // Clean up
    wolfSSL_free(ssl);
    close(clientfd);
    wolfSSL_CTX_free(ctx);
    close(sockfd);
    wolfSSL_Cleanup();

    printf("Done\n");

    return 0;
}
