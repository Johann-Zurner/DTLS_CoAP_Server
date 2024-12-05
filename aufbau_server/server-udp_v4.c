//server v4:UDP Socket + DTLS Handshake + CID + PSK
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_PORT	2444
#define BUFFER_SIZE	4096
#define CA_CERT_FILE 	"ecdsa-cert.pem"
#define KEY_FILE	"server-key.pem"
#define CERT_SERVER 	"server-cert.pem"
#define PSK_KEY 	"ddbbba39dace95ed"
#define PSK_IDENTITY 	"Client_identity"


unsigned int my_psk_server_callback(WOLFSSL* ssl, const char* identity,
                              unsigned char* key, unsigned int key_max_len) {
    memcpy(key, PSK_KEY, strlen(PSK_KEY));
    return strlen(PSK_KEY); 
}


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
    wolfSSL_CTX_use_psk_identity_hint(ctx, PSK_IDENTITY);
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_callback);

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
    wolfSSL_dtls_set_timeout_init(ssl, 4);

    wolfSSL_accept(ssl);

    ret = wolfSSL_dtls_cid_is_enabled(ssl);

    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
