//server v1:UDP Socket
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT		11111
#define BUFFER_SIZE		4096

int main()
{
    int 			sockfd;
    struct sockaddr_in		servAddr, clientAddr;
    const struct sockaddr*	servAddr_in;
    struct sockaddr*		clientAddr_in;
    socklen_t			clientAddrLen;
    char buf[BUFFER_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family 	= AF_INET;
    servAddr.sin_port		= htons(SERVER_PORT);
    servAddr.sin_addr.s_addr 	= htonl(INADDR_ANY);

    servAddr_in 	= (struct sockaddr*)&servAddr;
    clientAddr_in	= (struct sockaddr*)&clientAddr;
    bind(sockfd, servAddr_in, sizeof(servAddr));

    clientAddrLen = sizeof(clientAddr);
    recvfrom(sockfd, buf, BUFFER_SIZE, 0, clientAddr_in, &clientAddrLen);
    printf("Nachricht: %s\n", buf);

    return 0;
}
