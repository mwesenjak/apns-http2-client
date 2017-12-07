# apns-http2-client
simple CLI utility to interact with Apple Push Notification services

uses libnghttp2 - please have a look on their GitHub: [https://github.com/nghttp2/](https://github.com/nghttp2/)

## Requirements for building
You may either install the development packages or build these packages from source:

- openssl (tested on 1.0.2m)
- libnghttp2

## Building

Open the Makefile.  
Make sure that the library / include paths match on your system.  
Then:
  
~~~sh
make
./apns-http2-client
~~~

~mwesenjak