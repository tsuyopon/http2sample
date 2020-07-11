# http2client
test implementation for http2 client.

There are too many limitations about this source code.
- can access only https://<domain>/ at 1 times,   can not specify any entrypoint.
- completly blocking access
- could not parse HEADER Frames
- only handling "Literal Header Field Without Indexing".
- and a lot...

# Requrement
require openssl-1.1.0+ to compile this source code.

# Compile & Execution  
```
$ cd src/
$ make
$ ./http2client www.yahoo.co.jp
```

# Note
If you want to decrypt TLS packet and to analyze HTTP/2 frames, you should better modify SSLKEYLOGFILE. And set wireshark 「(Pre)-Master-Secret log filename」.
```
$ grep SSLKEYLOGFILE src/Definitions.h 
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
```
