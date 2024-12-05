//server v3:UDP Socket + DTLS Handshake + CID
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT		11111
#define BUFFER_SIZE		4096
#define CA_CERT_FILE 		"ecdsa-cert.pem"
#define KEY_FILE		"server-key.pem"
#define CERT_SERVER 		"server-cert.pem"

int main()
{
    int 			sockfd;
    struct sockaddr_in		servAddr, clientAddr;
    const struct sockaddr*	servAddr_in;
    struct sockaddr*		clientAddr_in;
    socklen_t			clientAddrLen;
    char 			buffer[BUFFER_SIZE];
    unsigned char 		connectionID[2];
    int				ret;
    WOLFSSL_CTX*		ctx;
    WOLFSSL*			ssl;
    WOLFSSL_METHOD*		method = wolfDTLSv1_3_server_method();

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family 	= AF_INET;
    servAddr.sin_port		= htons(SERVER_PORT);
    servAddr.sin_addr.s_addr 	= INADDR_ANY;

    servAddr_in 	= (struct sockaddr*)&servAddr;
    clientAddr_in	= (struct sockaddr*)&clientAddr;
    bind(sockfd, servAddr_in, sizeof(servAddr));
    clientAddrLen = sizeof(clientAddr);

    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    ctx = wolfSSL_CTX_new(method);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    wolfSSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, 0);
    wolfSSL_CTX_use_certificate_file(ctx, CERT_SERVER, WOLFSSL_FILETYPE_PEM);
    wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM);

    ssl = wolfSSL_new(ctx);

    wolfSSL_RAND_bytes(connectionID, sizeof(connectionID));
    wolfSSL_dtls_cid_use(ssl);
    ret = wolfSSL_dtls_cid_set(ssl, connectionID, sizeof(connectionID));
    if (ret != WOLFSSL_SUCCESS) {
        printf("\033[31mFailed to set CID. Error code: %d\033[0m\n", ret);
        printf("\033[31mError message: %s\033[0m\n", wolfSSL_ERR_reason_error_string(ret));
    } else {
        printf("\033[32mCID set successfully\033[0m\n");
    }

    recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);
    wolfSSL_dtls_set_peer(ssl, &clientAddr, clientAddrLen);
    wolfSSL_set_fd(ssl, sockfd);
    wolfSSL_accept(ssl);

    ret = wolfSSL_dtls_cid_is_enabled(ssl);
    if (ret == WOLFSSL_SUCCESS) {
        printf("\033[32mCID enabled after handshake\033[0m\n");
    }
    else {
        printf("\033[32mCID not enabled after handshake. Error code: %d\033[0m\n", ret);
    }

    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
