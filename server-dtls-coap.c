#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <coap3/coap.h>
#include <coap3/coap_pdu.h>

//#define USE_CID // Comment out to disable the use of Connection ID
#define CERTS //Comment out to use Pre-Shared Keys instead of Certficate Verfication
#define USE_DTLS_1_3 //Comment out to use DTLS 1.2 instead of 1.3
#define SHOW_WOLFSSL_DEBUG // Comment out to remove timestamps from debug logs

#define COAP_MAX_PDU_SIZE 128
#define PSK_IDENTITY "Client_identity"
#define PSK_KEY "\xdd\xbb\xba\x39\xda\xce\x95\xed\x12\x34\x56\x78\x90\xab\xcd\xef"
#define PSK_KEY_LEN 16

#ifdef NO_COLORS
#define GREEN ""
#define RED ""
#define RESET ""
#else
#define GREEN "\033[32m"
#define RED "\033[31m"
#define RESET "\033[0m"
#endif

#define BASE_PATH "/root/wolfssl/bin/server/"
#define SERVER_PORT 2444
#define BUFFER_SIZE 1024
#define SERVER_KEY BASE_PATH "certs/serverCert/key/server-ec-key.pem"
#define SERVER_CERT BASE_PATH "certs/serverCert/cert/server-cert-ce.pem"
#define ROOT_CA_DIRECTORY BASE_PATH "certs/rootCAs/rootCerts"
#define CID_SIZE 2

unsigned int my_psk_server_callback(WOLFSSL *ssl, const char *identity,
                                    unsigned char *key, unsigned int key_max_len);

void CustomLoggingCallback(const int logLevel, const char *const logMessage);

void printf_with_timestamp(const char *format, ...);

void cert_setup(WOLFSSL_CTX *ctx);
void show_supported_ciphers();

int main()
{
    int sockfd;
    struct sockaddr_in servAddr, clientAddr;
    const struct sockaddr *servAddr_in;
    struct sockaddr *clientAddr_in;
    socklen_t clientAddrLen;
    char buffer[BUFFER_SIZE], recLine[BUFFER_SIZE], cipher_buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN], client_ip_new[INET_ADDRSTRLEN];
    uint16_t client_port, client_port_new;
    int ret, err;
    unsigned char connectionID[2];
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
#ifdef USE_DTLS_1_3
    WOLFSSL_METHOD *method = wolfDTLSv1_3_server_method();
#else
    WOLFSSL_METHOD *method = wolfDTLSv1_2_server_method();
#endif

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERVER_PORT);
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    servAddr_in = (struct sockaddr *)&servAddr;
    clientAddr_in = (struct sockaddr *)&clientAddr;
    bind(sockfd, servAddr_in, sizeof(servAddr));
    clientAddrLen = sizeof(clientAddr);

    wolfSSL_Init();

#ifdef SHOW_WOLFSSL_DEBUG
#define PRINTF(format, ...) printf_with_timestamp(format, ##__VA_ARGS__)
    wolfSSL_SetLoggingCb(CustomLoggingCallback);
    wolfSSL_Debugging_ON();
    show_supported_ciphers();
#else
#define PRINTF(format, ...) printf(format, ##__VA_ARGS__)
#endif

    ctx = wolfSSL_CTX_new(method);

#ifdef CERTS
    ret = wolfSSL_CTX_load_verify_locations(ctx, NULL, ROOT_CA_DIRECTORY);
    if (ret == WOLFSSL_SUCCESS)
    {
        PRINTF(GREEN "CA-cert load success" RESET "\n");
    }
    else
    {
        PRINTF(RED "CA-cert fail. Error: %d" RESET "\n", ret);
        PRINTF(RED "Error message: %s" RESET "\n", wolfSSL_ERR_reason_error_string(ret));
    }

    ret = wolfSSL_CTX_use_certificate_file(ctx, SERVER_CERT, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS)
    {
        PRINTF(GREEN "Server-cert load success" RESET "\n");
    }
    else
    {
        PRINTF(RED "Server-cert fail. Error: %d" RESET "\n", ret);
    }

    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, WOLFSSL_FILETYPE_PEM);
    if (ret == WOLFSSL_SUCCESS)
    {
        PRINTF(GREEN "Key load success" RESET "\n");
    }
    else
    {
        PRINTF(RED "Key fail. Error: %d" RESET "\n", ret);
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
#else
    wolfSSL_CTX_use_psk_identity_hint(ctx, PSK_IDENTITY);
    wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_callback);
#endif
    // wolfSSL_CTX_set_cipher_list(ctx, "PSK-AES128-GCM-SHA256"); //Force specific ciphers

    ssl = wolfSSL_new(ctx);

#ifdef USE_CID
    wolfSSL_RAND_bytes(connectionID, sizeof(connectionID));
    wolfSSL_dtls_cid_use(ssl);
    ret = wolfSSL_dtls_cid_set(ssl, connectionID, sizeof(connectionID));
#endif
    recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);

    wolfSSL_dtls_set_peer(ssl, &clientAddr, clientAddrLen);
    wolfSSL_set_fd(ssl, sockfd);
    wolfSSL_dtls_set_timeout_init(ssl, 10);
    ret = wolfSSL_accept(ssl);
    if (ret == WOLFSSL_SUCCESS)
    {
        PRINTF(GREEN "Handshake success" RESET "\n");
        strcpy(client_ip, inet_ntoa(((struct sockaddr_in *)clientAddr_in)->sin_addr));
        client_port = ntohs(((struct sockaddr_in *)clientAddr_in)->sin_port);
    }
    else
    {
        err = wolfSSL_get_error(ssl, ret);
        PRINTF(RED "Error during wolfSSL_read: %d" RESET "\n", err);
        goto cleanup;
    }

    while (1)
    {
        PRINTF(GREEN "Receiving packet........" RESET "\n");
        ssize_t receivedSize = recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);

        if (receivedSize == -1)
        {
            PRINTF(GREEN "Socket waiting for packet... " RESET "\n");
            continue;
        }
        strcpy(client_ip_new, inet_ntoa(((struct sockaddr_in *)clientAddr_in)->sin_addr));
        client_port_new = ntohs(((struct sockaddr_in *)clientAddr_in)->sin_port);
        PRINTF(GREEN "client_ip: %s; client_ip_new: %s" RESET "\n", client_ip, client_ip_new);
        PRINTF(GREEN "client_port: %u; client_port_new: %u" RESET "\n", client_port, client_port_new);
        if (wolfSSL_dtls_cid_is_enabled(ssl) == WOLFSSL_SUCCESS)
        {

            if (strcmp(client_ip, client_ip_new) != 0 || client_port != client_port_new)
            {
                PRINTF(GREEN "IP or port has changed! Checking ConnectionID" RESET "\n");
                strcpy(client_ip, client_ip_new);
                client_port = client_port_new;
                const unsigned char *extractedCID = wolfSSL_dtls_cid_parse((unsigned char *)buffer, receivedSize, sizeof(connectionID));
                PRINTF(GREEN "Extracted CID: " RESET);
                for (unsigned int i = 0; i < sizeof(connectionID); i++)
                {
                    printf(GREEN "%02X" RESET, extractedCID[i]);
                }
                printf("\n");
                PRINTF("\n");
                unsigned char storedCID[CID_SIZE];
                wolfSSL_dtls_cid_get_rx(ssl, storedCID, sizeof(storedCID));
                PRINTF(GREEN "Stored CID: " RESET);
                for (unsigned int i = 0; i < sizeof(storedCID); i++)
                {
                    printf(GREEN "%02X" RESET, storedCID[i]);
                }
                printf("\n");
                PRINTF("\n");
                if (memcmp(extractedCID, storedCID, CID_SIZE) == 0)
                {
                    PRINTF(GREEN "Extracted CID from received Packet and stored CID are equal" RESET "\n");
                    wolfSSL_inject(ssl, buffer, receivedSize);
                    recvfrom(sockfd, buffer, sizeof(buffer), 0, clientAddr_in, &clientAddrLen);
                    wolfSSL_dtls_set_peer(ssl, clientAddr_in, clientAddrLen);
                }
                else
                {
                    PRINTF(RED "Extracted CID from received Packet and stored CID are NOT equal" RESET "\n");
                    goto reset_session;
                }
            }
        }
        else if (strcmp(client_ip, client_ip_new) != 0 || client_port != client_port_new)
        {
            // CID is not enabled and IP/Port mismatch
            PRINTF(RED "IP or port has changed without CID. Terminating session." RESET "\n");
            goto reset_session; // Go to reset session logic
        }
        PRINTF(GREEN "Reading packet with wolfssl_read..." RESET "\n");
        ret = wolfSSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (ret != WOLFSSL_SUCCESS)
        {
            err = wolfSSL_get_error(ssl, ret);
            if (err == WOLFSSL_ERROR_ZERO_RETURN) {
                PRINTF(GREEN "Got close notify; closing session..." RESET"\n");
                goto cleanup;
            }

        }
        if ((buffer[0] & 0xC0) != 0x40)
        {
            PRINTF("Invalid CoAP version or type\n");
        }
        if (ret <= 0)
        {
            err = wolfSSL_get_error(ssl, ret);
            PRINTF(RED "Error during wolfSSL_read: %d" RESET "\n", err);
        }
        else
        {
            PRINTF(GREEN "Read success" RESET "\n");
            recLine[ret] = '\0';
        }
        for (int i = 0; i < ret; i++)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
        PRINTF("\n");
        coap_pdu_t *received_pdu = coap_pdu_init(0, 0, 0, COAP_MAX_PDU_SIZE);
        if (coap_pdu_parse(COAP_PROTO_UDP, (const uint8_t *)buffer, ret, received_pdu) == 0)
        {
            if ((buffer[0] & 0xC0) != 0x40)
            {
                printf("Invalid CoAP version or type\n");
            }
            PRINTF("Failed to parse CoAP message\n");
        }
        const uint8_t *payload;
        size_t payload_len;

        // Use coap_get_data to get payload and its length
        if (coap_get_data(received_pdu, &payload_len, &payload))
        {
            char temperature[payload_len + 1];
            memcpy(&temperature, payload, payload_len);
            temperature[payload_len] = '\0';
            PRINTF(GREEN "Payload (Temperature): %s°C" RESET "\n", temperature);
        }
        coap_mid_t message_id = coap_pdu_get_mid(received_pdu);
        PRINTF(GREEN "MID: %u" RESET "\n", message_id);

        const coap_bin_const_t token_data = coap_pdu_get_token(received_pdu);
        const uint8_t *token = token_data.s;  // Pointer to the token bytes
        size_t token_len = token_data.length; // Length of the token

        // Print the token
        if (token_len > 0)
        {
            PRINTF("Token Length: %zu\n", token_len);
            PRINTF("Token Data (hex): ");
            for (size_t i = 0; i < token_len; i++)
            {
                printf("%02X ", token[i]); // Print each byte in hexadecimal
            }
            printf("\n");
            PRINTF("\n");
        }
        // Check if it’s a confirmable message (COAP_MESSAGE_CON)
        if (coap_pdu_get_type(received_pdu) == COAP_MESSAGE_CON)
        {
            PRINTF(GREEN "It's a confirmable COP message" RESET "\n");
            uint8_t ack_buffer[COAP_MAX_PDU_SIZE]; // Buffer for constructing the acknowledgment
            size_t offset = 0;                     // Offset for constructing the buffer

            // Step 1: Set CoAP header
            ack_buffer[offset++] = 0x60 | (token_len & 0x0F); // Version = 1 (0b01), Type = ACK (0b10), Token length = 0
            ack_buffer[offset++] = 0x44;                         // Code = 2.04 (Success changed)
            ack_buffer[offset++] = (message_id >> 8) & 0xFF;  // Message ID (high byte)
            ack_buffer[offset++] = message_id & 0xFF;         // Message ID (low byte)

            // Step 2: Add the token manually (if present)
            if (token_len > 0)
            {
                memcpy(&ack_buffer[offset], token, token_len);
                offset += token_len;
            }
            PRINTF("Ack_buffer\n");
            for (size_t i = 0; i < offset; i++)
            {
                printf("%02X ", ack_buffer[i]); // Print each byte in hexadecimal
            }
            printf("\n");
            PRINTF("\n");
            // Total length of the acknowledgment
            size_t total_len = offset;

            // Step 3: Send the acknowledgment
            ret = wolfSSL_write(ssl, ack_buffer, total_len);
            if (ret != total_len)
            {
                PRINTF(RED "Failed to send CoAP acknowledgment" RESET "\n");
            }
            else
            {
                PRINTF(GREEN "CoAP acknowledgment sent successfully" RESET "\n");
            }
        }
        else
        {
            PRINTF("Received non-confirmable or other CoAP message\n");
        }
        coap_delete_pdu(received_pdu);
        continue;

    reset_session:
        PRINTF(RED "Resetting DTLS session for new handshake." RESET "\n");
        // wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        // ssize_t receivedSize = recvfrom(sockfd, buffer, sizeof(buffer), MSG_PEEK, clientAddr_in, &clientAddrLen);
        PRINTF("Buffer contents: ");
        for (int i = 0; i < receivedSize; i++)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
        ssl = wolfSSL_new(ctx);
        wolfSSL_dtls_set_peer(ssl, clientAddr_in, clientAddrLen);
        wolfSSL_set_fd(ssl, sockfd);
        wolfSSL_dtls_set_timeout_init(ssl, 7);

        ret = wolfSSL_accept(ssl);
        if (ret == WOLFSSL_SUCCESS)
        {
            PRINTF(GREEN "New handshake success" RESET "\n");
            strcpy(client_ip, inet_ntoa(((struct sockaddr_in *)clientAddr_in)->sin_addr));
            client_port = ntohs(((struct sockaddr_in *)clientAddr_in)->sin_port);
            continue;
        }
        else
        {
            err = wolfSSL_get_error(ssl, ret);
            PRINTF(RED "Error during handshake: %d" RESET "\n", err);
            goto cleanup;
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

void CustomLoggingCallback(const int logLevel, const char *const logMessage)
{
    struct timeval tv;
    struct tm *timeinfo;

    // Get the current time with microseconds
    gettimeofday(&tv, NULL);
    timeinfo = localtime(&tv.tv_sec);

    // Print time with hours, minutes, seconds, and microseconds
    fprintf(stderr, "[%02d:%02d:%02d.%06ld] %s\n",
            timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, tv.tv_usec, logMessage);
}

void printf_with_timestamp(const char *format, ...)
{
    struct timeval tv;
    struct tm *timeinfo;

    // Get the current time
    gettimeofday(&tv, NULL);
    timeinfo = localtime(&tv.tv_sec);

    // Print timestamp with hours, minutes, seconds, and microseconds
    fprintf(stdout, "[%02d:%02d:%02d.%06ld] ",
            timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, tv.tv_usec);

    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}

unsigned int my_psk_server_callback(WOLFSSL *ssl, const char *identity,
                                    unsigned char *key, unsigned int key_max_len)
{
    memcpy(key, PSK_KEY, PSK_KEY_LEN);
    return PSK_KEY_LEN;
}

void show_supported_ciphers()
{
    uint8_t cipher_buffer[2048];
    wolfSSL_get_ciphers(cipher_buffer, BUFFER_SIZE);
    for (char *p = (char *)cipher_buffer; *p; p++)
    {
        if (*p == ':')
        {
            *p = '\n';
        }
    }
    printf("Enabled Ciphers:\n%s\n", cipher_buffer);
}
