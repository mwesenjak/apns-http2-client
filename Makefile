# Makefile for apns-http2-client
#
# adjust CFLAGS to your needs (openssl / libnghttp2 paths)

CFLAGS = -I/usr/local/include -I/usr/local/opt/openssl/include -L/usr/local/lib -L/opt/local/lib -lnghttp2 -lssl -lcrypto

all:
	gcc -o apns-http2-client main.c $(CFLAGS)
clean:
	rm apns-http2-client

