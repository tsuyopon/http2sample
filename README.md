...This repository is UNDER CONSTRUCTING...

# http2client
test implementation for http2 client.

There are too many limitations about this source code.
- can access only https://\<domain\>/ at 1 times,   can not specify any entrypoint.
- completly blocking access
- and a lot...

# Requrement
- GCC 5 or lator (std=c++17 support compiler)
  - https://gcc.gnu.org/projects/cxx-status.html#cxx17
- require openssl-1.1.0+ to compile this source code.

# Compile & Execution  
- compile
```
$ cd src/
$ make
```

- execute
you can specify target domain.
```
$ ./http2client -u https://example.com/hoge/fuga/piyo
```

# Note
If you want to decrypt TLS packet and to analyze HTTP/2 frames, you should better modify SSLKEYLOGFILE. And set wireshark key settings. Preferences -> Protocol -> TLS -> 「(Pre)-Master-Secret log filename」
```
$ grep SSLKEYLOGFILE src/Definitions.h 
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
```
