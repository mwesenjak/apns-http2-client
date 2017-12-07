//
//  main.h
//  apns-http2-client
//
//  Created by Manu a.k.a Chef von Australien on 07/12/2017.
//  Copyright © 2017 @mwesenjak. All rights reserved.
//

#ifndef main_h
#define main_h

#include <stdio.h>
#include <strings.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/poll.h>

#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <nghttp2/nghttp2.h>

// -------------------------------------------------
// GENERAL DEFINES

#define INFO(s) printf("[INFO]\t %s\n", s)
#define WARN(s) printf("[WARN]\t %s\n", s)
#define ERR(s) printf("[ERR]\t %s\n", s)

// These are the APNs servers as specified by Apple
#define APNS_SANDBOX "api.development.push.apple.com"
#define APNS_PRODUCTION "api.push.apple.com"
#define APNS_PORT 443

// API notification path
#define APNS_BASE_PATH "/3/device/"

typedef enum apns_client_mode {
    SANDBOX = 0,
    PRODUCTION = 1
} apns_mode_t;

typedef enum apns_input_output_operations {
    IO_NONE,
    WANT_READ,
    WANT_WRITE
} apns_io_ops;

typedef struct apns_certificates_context {
    char *certfile;
    char *keyfile;
    char *keypass;
} apns_certs_t;

typedef struct apns_crypto_context {
    SSL_CTX *ssl_ctx;
    SSL *ssl;
} apns_crypto_t;

typedef struct apns_input_output_context {
    nghttp2_session *session;
    int keepalive;
    int want_io;
} apns_io_t;

typedef struct apns_client_context {
    apns_certs_t certs;
    char *topic;
    apns_mode_t mode;
    apns_crypto_t crypto;
    int connfd;
    apns_io_t io;
} apns_context_t;

// --------------------------------------------------
// FORWARD DECLARATIONS

void fail(const char *message);

// --------------------------------------------------
// NGHTTP2 MACROS

#define MAKE_NV(NAME, VALUE)                                                \
{                                                                           \
(uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,     \
NGHTTP2_NV_FLAG_NONE                                                        \
}

#define MAKE_NV_CS(NAME, VALUE)                                             \
{                                                                           \
(uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),         \
NGHTTP2_NV_FLAG_NONE                                                        \
}

#endif /* main_h */
