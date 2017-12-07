//
//  main.c
//  apns-http2-client
//
//  Created by Manu a.k.a Chef von Australien on 07/12/2017.
//  Copyright © 2017 @mwesenjak. All rights reserved.
//

#include "main.h"

// -------------------------------------------------------
// CALLBACKS

static int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
    int ret;
    ret = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (ret <= 0) {
        fail("Server did not advertise HTTP/2 protocol");
    }
    return SSL_TLSEXT_ERR_OK;
}

static ssize_t apns_data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                       uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    size_t len = 0;
    if (length != 0) {
        uint8_t *payload = (uint8_t *)source->ptr;
        len = strlen((char *)payload);
        memcpy(buf, payload, len);
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return len;
}


// NOTE:
// following callbacks have been taken straight from nghttp2's source;
// some modifications may have been done though. :P
//
// see https://github.com/nghttp2 for full source

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
    apns_context_t *ctx;
    int ret;
    
    // double referencing + de-referencing != referencing .. ugly as fuck :)
    ctx = *(apns_context_t **)user_data;
    ctx->io.want_io = IO_NONE;
    ERR_clear_error();
    ret = SSL_write(ctx->crypto.ssl, data, (int)length);
    if (ret <= 0) {
        int err = SSL_get_error(ctx->crypto.ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            ctx->io.want_io =
            (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            ret = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            ret = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return ret;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data) {
    apns_context_t *ctx;
    int ret;
    
    ctx = *(apns_context_t **)user_data;
    ctx->io.want_io = IO_NONE;
    ERR_clear_error();
    ret = SSL_read(ctx->crypto.ssl, buf, (int)length);
    if (ret < 0) {
        int err = SSL_get_error(ctx->crypto.ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            ctx->io.want_io =
            (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            ret = NGHTTP2_ERR_WOULDBLOCK;
        } else {
            ret = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else if (ret == 0) {
        ret = NGHTTP2_ERR_EOF;
    }
    return ret;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    size_t i;
    
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
                const nghttp2_nv *nva = frame->headers.nva;
                printf("[INFO] C ----------------------------> S (HEADERS)\n");
                for (i = 0; i < frame->headers.nvlen; ++i) {
                    fwrite(nva[i].name, 1, nva[i].namelen, stdout);
                    printf(": ");
                    fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
                    printf("\n");
                }
            }
            break;
        case NGHTTP2_RST_STREAM:
            printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
            break;
        case NGHTTP2_GOAWAY:
            printf("[INFO] C ----------------------------> S (GOAWAY)\n");
            break;
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    size_t i;
    
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                const nghttp2_nv *nva = frame->headers.nva;
                struct Request *req;
                req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
                if (req) {
                    printf("[INFO] C <---------------------------- S (HEADERS)\n");
                    for (i = 0; i < frame->headers.nvlen; ++i) {
                        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
                        printf(": ");
                        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
                        printf("\n");
                    }
                }
            }
            break;
        case NGHTTP2_RST_STREAM:
            printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
            break;
        case NGHTTP2_GOAWAY:
            printf("[INFO] C <---------------------------- S (GOAWAY)\n");
            break;
    }
    return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
    apns_context_t *ctx;
    
    ctx = nghttp2_session_get_stream_user_data(session, stream_id);
    if (ctx) {
        if (!ctx->io.keepalive) {
            int ret;
            ret = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
            
            if (ret != 0) {
                fail("nghttp2_session_terminate_session");
            }
        }
    }
    return 0;
}

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
    apns_context_t *ctx;
    
    ctx = nghttp2_session_get_stream_user_data(session, stream_id);
    if (ctx) {
        printf("[INFO] C <---------------------------- S (DATA chunk)\n"
               "%lu bytes\n",
               (unsigned long int)len);
        fwrite(data, 1, len, stdout);
        printf("\n");
    }
    return 0;
}


// -------------------------------------------------------

void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks) {
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
}

void print_header() {
    printf("==================\n");
    printf("APNS HTTP/2 CLIENT\n");
    printf("==================\n");
    printf("2017 @mwesenjak\n");
    printf("uses libnghttp2 - https://github.com/nghttp2\n\n");
}

void print_usage(char *bin) {
    printf("usage: %s CERT KEY PASSPHRASE TOPIC MODE\n\n", bin);
    printf("\tCERT\t\t- APNS client certificate in .pem format\n");
    printf("\tKEY\t\t- APNS client PRIVATE key in .pem format\n");
    printf("\tPASSPHRASE\t- passphrase for KEY\n");
    printf("\tTOPIC\t\t- usually your bundle ID of the app (see: Apple - Communicating with APNs)\n");
    printf("\tMODE\t\t- either SANDBOX (default) or PRODUCTION (depending on your certs)\n");
}

void fail(const char *message) {
    ERR(message);
    exit(1);
}

int initialize_connection(apns_context_t *ctx) {
    struct addrinfo hints;
    int fd = -1;
    int ret;
    char service[NI_MAXSERV];
    struct addrinfo *res, *rp;
    snprintf(service, sizeof(service), "%u", APNS_PORT);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if(ctx->mode == PRODUCTION) {
        ret = getaddrinfo(APNS_PRODUCTION, service, &hints, &res);
    } else {
        ret = getaddrinfo(APNS_SANDBOX, service, &hints, &res);
    }
    if (ret != 0) {
        fail("failed to get addr info");
    }
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) {
            continue;
        }
        while ((ret = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
               errno == EINTR)
            ;
        if (ret == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

void setup_crypto(apns_context_t *ctx) {
    ctx->crypto.ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if(ctx->crypto.ssl_ctx == NULL) {
        fail("failed to initialize openssl context");
    }
    SSL_CTX_set_options(ctx->crypto.ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ctx->crypto.ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx->crypto.ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_next_proto_select_cb(ctx->crypto.ssl_ctx, select_next_proto_cb, NULL);
    
    ctx->crypto.ssl = SSL_new(ctx->crypto.ssl_ctx);
    if(ctx->crypto.ssl == NULL) {
        fail("failed to initialize openssl struct");
    }
    
    EVP_PKEY *privKey = NULL;
    X509 *cert = NULL;
    FILE *tfile = NULL;
    
    // reading certificate and private key
    tfile = fopen(ctx->certs.certfile, "r");
    if(tfile == NULL) {
        fail("failed to open certificate file");
    }
    PEM_read_X509(tfile, &cert, NULL, NULL);
    if(cert == NULL) {
        fclose(tfile);
        fail("failed to read certificate file (invalid/corrupt?)");
    }
    fclose(tfile);
    
    tfile = fopen(ctx->certs.keyfile, "r");
    if(tfile == NULL) {
        fail("failed to open key file");
    }
    PEM_read_PrivateKey(tfile, &privKey, NULL, ctx->certs.keypass);
    if(privKey == NULL) {
        fclose(tfile);
        fail("failed to read key file (invalid/corrupt/invalid passphrase?)");
    }
    fclose(tfile);
    
    int ret = 0;
    
    // instruct openssl to use our specified certificate / key
    ret = SSL_use_certificate(ctx->crypto.ssl, cert);
    if(ret != 1) {
        fail("failed to set certificate");
    }
    ret = SSL_use_PrivateKey(ctx->crypto.ssl, privKey);
    if(ret != 1) {
        fail("failed to set private key");
    }
    // all done.
}

void ssl_handshake(apns_context_t *ctx) {
    int ret = 0, flags = 0, val = 1;
    // set descriptor ...
    if (SSL_set_fd(ctx->crypto.ssl, ctx->connfd) == 0) {
        fail("SSL_set_fd: could not set connection descriptor");
    }
    ERR_clear_error();
    // ... and connect ...
    ret = SSL_connect(ctx->crypto.ssl);
    if (ret <= 0) {
        fail("SSL_connect: could not establish TLS");
    }
    // ... and make that thing non-blocking
    while ((flags = fcntl(ctx->connfd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1) {
        fail("fcntl: could not get current flags");
    }
    while ((ret = fcntl(ctx->connfd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (ret == -1) {
        fail("fcntl: could not set updated flags (O_NONBLOCK)");
    }
    ret = setsockopt(ctx->connfd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
    if (ret == -1) {
        fail("setsockopt failed");
    }
}

void initialize_client(apns_context_t *ctx) {
    int ret = 0;
    nghttp2_session_callbacks *callbacks;
    
    ctx->connfd = initialize_connection(ctx);
    if(ctx->connfd < 0) {
        fail("failed to initialize connection");
    }
    
    // set up openssl with cert/key
    setup_crypto(ctx);
    
    // do handshake
    ssl_handshake(ctx);
    
    // setup callbacks
    ret = nghttp2_session_callbacks_new(&callbacks);
    if(ret != 0) {
        fail("failed to register callbacks");
    }
    setup_nghttp2_callbacks(callbacks);
    
    // create new session
    ret = nghttp2_session_client_new(&ctx->io.session, callbacks, &ctx);
    
    // once created and assigned, we do not need that callback struct anymore
    nghttp2_session_callbacks_del(callbacks);
    if (ret != 0) {
        fail("failed to create session");
    }
    ret = nghttp2_submit_settings(ctx->io.session, NGHTTP2_FLAG_NONE, NULL, 0);
    if (ret != 0) {
        fail("failed to apply settings to session");
    }
    
    // keep connections active as long as possible
    ctx->io.keepalive = 1;
}

void io_dispatch(apns_context_t *ctx) {
    int ret = 0;
    ret = nghttp2_session_recv(ctx->io.session);
    if (ret != 0) {
        fail("nghttp2_session_recv failed");
    }
    ret = nghttp2_session_send(ctx->io.session);
    if (ret != 0) {
        fail("nghttp2_session_send failed");
    }
}

int32_t do_request(apns_context_t *ctx, const char *path, const char *data) {
    int32_t stream_id;
    
    // setup header array
    const nghttp2_nv nva[] = {
        MAKE_NV(":method", "POST"),
        {(uint8_t *)":path", (uint8_t *)path, sizeof(":path") - 1, strlen(path) },
        MAKE_NV(":scheme", "https"),
        {(uint8_t *)"apns-topic", (uint8_t *)ctx->topic, sizeof("apns-topic") - 1, strlen(ctx->topic)},
        MAKE_NV("accept", "*/*"),
        MAKE_NV("user-agent", "nghttp2/" NGHTTP2_VERSION)
    };
    
    // we need a data source to deliver our data
    nghttp2_data_source data_src;
    nghttp2_data_provider data_prd;
    
    data_src.fd = 2;
    data_src.ptr = (char *)data;
    
    // also, set the read callback appropriately
    data_prd.source = data_src;
    data_prd.read_callback = apns_data_source_read_callback;
    
    // showtime
    stream_id = nghttp2_submit_request(ctx->io.session, NULL, nva, sizeof(nva) / sizeof(nva[0]), &data_prd, ctx);
    
    // if all went right, we should have a positive stream_id now
    if (stream_id < 0) {
        fail("nghttp2_submit_request failed :(");
    }
    
    INFO("message delivered");
    return stream_id;
}

void parse_line(char *input, char *path, char *payload) {
    char *ori = input;
    size_t len = strlen(input);
    // check for invalid input
    if(len <= 0) {
        return;
    }
    
    long trimpos = 0;
    while (*(++input) != ' ' && *input != 0x0);
    if(*input == 0x0) {
        return;
    }
    trimpos = input - ori;
    strcpy(path, APNS_BASE_PATH);
    memcpy(path+strlen(APNS_BASE_PATH), ori, trimpos);
    memcpy(payload, ori+trimpos+1, len - trimpos-2);
}

void do_poll(apns_context_t *ctx, struct pollfd *pollfd) {
    pollfd->events = 0;
    if (nghttp2_session_want_read(ctx->io.session) ||
        ctx->io.want_io == WANT_READ) {
        pollfd->events |= POLLIN;
    }
    if (nghttp2_session_want_write(ctx->io.session) ||
        ctx->io.want_io == WANT_WRITE) {
        pollfd->events |= POLLOUT;
    }
}

void run_client(apns_context_t *ctx) {
    nfds_t npollfds = 1;
    struct pollfd pollfds[1];
    
    initialize_client(ctx);
    
    // DEVELOPERS:
    // implement your custom features here...
    
    // now we should be ready to go...
    // let's build those requests :)
    INFO("client successfully initialized and connected");
    INFO("submit your requests as follows:");
    INFO("<device_token> <payload>");
    INFO("enter 'quit' or 'exit' to close the session");
    
    while (1) {
        // interactive session ftw
        printf("\nAPNs> ");
        char buf[2048] = {0}, path[2048] = {0}, payload[2048] = {0};
        fgets(buf, 2048, stdin);
        
        if (strstr(buf, "quit") == buf || strstr(buf, "exit") == buf) {
            nghttp2_session_terminate_session(ctx->io.session, 0);
            break;
        }
        
        parse_line(buf, path, payload);
        
        // Submit the HTTP request to the outbound queue.
        do_request(ctx, path, payload);
        
        pollfds[0].fd = ctx->connfd;
        do_poll(ctx, pollfds);
        
        /* Event loop */
        while (nghttp2_session_want_read(ctx->io.session) ||
               nghttp2_session_want_write(ctx->io.session)) {
            int nfds = poll(pollfds, npollfds, -1);
            if (nfds == -1) {
                fail("poll failed");
            }
            if (pollfds[0].revents & (POLLIN | POLLOUT)) {
                io_dispatch(ctx);
            }
            if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
                fail("Connection error");
            }
            do_poll(ctx, pollfds);
            break;
        }
    }
    
    // clean up
    nghttp2_session_del(ctx->io.session);
    SSL_shutdown(ctx->crypto.ssl);
    SSL_free(ctx->crypto.ssl);
    SSL_CTX_free(ctx->crypto.ssl_ctx);
    shutdown(ctx->connfd, SHUT_WR);
    close(ctx->connfd);
}

int main(int argc, char **argv, char **envp) {
    print_header();
    
    if(argc != 6) {
        print_usage(argv[0]);
        return 1;
    }
    
    // initializing openssl library
    SSL_load_error_strings();
    SSL_library_init();
    
    // set user params
    apns_context_t ctx;
    ctx.certs.certfile = argv[1];
    ctx.certs.keyfile = argv[2];
    ctx.certs.keypass = argv[3];
    ctx.topic = argv[4];
    
    if(!strcmp(argv[5], "PRODUCTION")) {
        INFO("PRODUCTION environment selected");
        ctx.mode = PRODUCTION;
    } else if(!strcmp(argv[5], "SANDBOX")) {
        INFO("SANDBOX environment selected");
        ctx.mode = SANDBOX;
    } else {
        INFO("unknown mode. defaulting to SANDBOX!");
        ctx.mode = SANDBOX;
    }
    
    // and start the whole thing
    run_client(&ctx);
    
    return 0;
}
