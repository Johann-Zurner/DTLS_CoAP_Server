//server-v5:UDP Socket + DTLS handshake + CID + working Certs (beide Seiten)
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#ifdef NO_COLORS
    #define GREEN ""
    #define RED   ""
    #define RESET ""
#else
    #define GREEN "\033[32m"
    #define RED   "\033[31m"
    #define RESET "\033[0m"
#endif

#define BASE_PATH               "/root/wolfssl/bin/server/"
#define SERVER_PORT             2444
#define BUFFER_SIZE             4096
#define SERVER_KEY              BASE_PATH "certs/serverCert/key/server-key1.pem"
#define SERVER_CERT             BASE_PATH "certs/serverCert/cert/server-cert1.pem"
#define ROOT_CA_DIRECTORY       BASE_PATH "certs/rootCAs/rootCerts"
#define CID_SIZE                2

int main()
{
    int                         sockfd;
    struct sockaddr_in          servAddr, clientAddr;
    const struct sockaddr*      servAddr_in;
    struct sockaddr*            clientAddr_in;
    socklen_t                   clientAddrLen;
    char                        buffer[BUFFER_SIZE], recLine[BUFFER_SIZE];
    char 			client_ip[INET_ADDRSTRLEN], client_ip_new[INET_ADDRSTRLEN];
    uint16_t			client_port, client_port_new;
    int                         ret, err;
    unsigned char               connectionID[2];
    WOLFSSL_CTX*                ctx;
    WOLFSSL*                    ssl;
    WOLFSSL_METHOD*             method = wolfDTLSv1_2_server_method();

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family         = AF_INET;
    servAddr.sin_port           = htons(SERVER_PORT);
    servAddr.sin_addr.s_addr    = htonl(INADDR_ANY);

    servAddr_in         = (struct sockaddr*)&servAddr;
    clientAddr_in       = (struct sockaddr*)&clientAddr;
    bind(sockfd, servAddr_in, sizeof(servAddr));
    clientAddrLen = sizeof(clientAddr);

    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    ctx = wolfSSL_CTX_new(method);
    ret = wolfSSL_CTX_load_verify_locations(ctx, NULL, ROOT_CA_DIRECTORY);
    if (ret == WOLFSSL_SUCCESS) {
        printf(GREEN "CA-cert load success" RESET "\n");
    }
    else {
        printf(RED "CA-cert fail. Error: %d" RESET "\n", ret);
        printf(RED "Error message: %s" RESET "\n", wolfSSL_ERR_reason_error_string(ret));
    }

    ret = wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS) {
        printf(GREEN "Server-cert load success" RESET "\n");
    }
    else {
        printf(RED "Server-cert fail. Error: %d" RESET "\n", ret);
    }

    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS) {
        printf(GREEN "Key load success" RESET "\n");
    }
    else {
        printf(RED "Key fail. Error: %d" RESET "\n", ret);
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);

    ssl = wolfSSL_new(ctx);

    wolfSSL_RAND_bytes(connectionID, sizeof(connectionID));
    wolfSSL_dtls_cid_use(ssl);
    ret = wolfSSL_dtls_cid_set(ssl, connectionID, sizeof(connectionID));
    if (ret == WOLFSSL_SUCCESS)
    {
            printf(GREEN "---CID set successfully---" RESET "\n");
    }
    else
    {
            printf(RED "---CID not set successfully--- Error code: %d" RESET "\n", ret);
    }
    wolfSSL_dtls_set_peer(ssl, &clientAddr, clientAddrLen);
    wolfSSL_set_fd(ssl, sockfd);
    wolfSSL_dtls_set_timeout_init(ssl, 7);
    wolfSSL_accept(ssl);
    if (ret == WOLFSSL_SUCCESS)
        {
                printf(GREEN "Handshake success" RESET "\n");
		strcpy(client_ip, inet_ntoa(((struct sockaddr_in *)clientAddr_in)->sin_addr));
		client_port = ntohs(((struct sockaddr_in *)clientAddr_in)->sin_port);
        }
        else
        {
                printf(RED "Handshake failed. Error code: %d" RESET "\n", ret);
		goto cleanup;
        }

    ret = wolfSSL_dtls_cid_is_enabled(ssl);

    while (1) {
        printf(GREEN "...New recvfrom........" RESET "\n");
        ssize_t receivedSize = recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);
        printf("Buffer contents: ");
        for (int i = 0; i < receivedSize; i++) {
	        printf("%02X ", (unsigned char) buffer[i]);
        }
        printf("\nReceived size: %zd\n", receivedSize);

        if (receivedSize == -1)
	{
                printf(GREEN "Socket waiting: %s" RESET "\n", strerror(errno));
                continue;
        }
	strcpy(client_ip_new, inet_ntoa(((struct sockaddr_in *)clientAddr_in)->sin_addr));
	client_port_new = ntohs(((struct sockaddr_in *)clientAddr_in)->sin_port);
	printf(GREEN "client_ip: %s; client_ip_new: %s" RESET "\n", client_ip,client_ip_new);
	printf(GREEN "client_port: %u; client_port_new: %u" RESET "\n", client_port, client_port_new);
	if (strcmp(client_ip, client_ip_new) != 0 || client_port != client_port_new) {
 	       	printf(GREEN "IP or port has changed! Checking ConnectionID" RESET "\n");
                strcpy(client_ip, client_ip_new);
               	client_port = client_port_new;
		const unsigned char* extractedCID = NULL;
        	wolfSSL_dtls_cid_parse((unsigned char*)buffer, receivedSize, &extractedCID, sizeof(connectionID));
        	printf(GREEN "Extracted CID: " RESET);
        	for (unsigned int i = 0; i < sizeof(connectionID); i++) {
            		printf(GREEN "%02X" RESET, extractedCID[i]);
        	}
        	printf("\n");
        	unsigned char storedCID[CID_SIZE];
        	wolfSSL_dtls_cid_get_rx(ssl, storedCID, sizeof(storedCID));
        	printf(GREEN "Stored CID: " RESET);
        	for (unsigned int i = 0; i < sizeof(storedCID); i++) {
           			printf(GREEN "%02X" RESET, storedCID[i]);
        	}
        	printf("\n");
  		if (memcmp(extractedCID, storedCID, CID_SIZE) == 0) {
               		printf(GREEN "Extracted CID from received Packet and stored CID are equal" RESET "\n");
	        	wolfSSL_inject(ssl, buffer, receivedSize);
			recvfrom(sockfd, buffer, sizeof(buffer), 0, clientAddr_in, &clientAddrLen);
           		wolfSSL_dtls_set_peer(ssl, clientAddr_in, clientAddrLen);
        	} else {
               		printf(RED "Extracted CID from received Packet and stored CID are NOT equal" RESET "\n");
        	}
	}
        ret = wolfSSL_read(ssl, recLine, sizeof(recLine) - 1);
        if (ret <= 0) {
                err = wolfSSL_get_error(ssl, ret);
                printf(RED "Error during wolfSSL_read: %d" RESET "\n", err);
        } else {
                printf(GREEN "Read success" RESET "\n");
                recLine[ret] = '\0';
                printf(GREEN "%s" RESET "\n", recLine);
        }
    }
cleanup:
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}
