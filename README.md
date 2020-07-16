...This repository is UNDER CONSTRUCTING...

# http2client
test implementation for http2 client.

There are too many limitations about this source code.
- can access only https://\<domain\>/ at 1 times,   can not specify any entrypoint.
- completly blocking access
- and a lot...

# Requrement
require openssl-1.1.0+ to compile this source code.

# Compile & Execution  
- compile
```
$ cd src/
$ make
```

- execute
you can specify target domain.
```
$ ./http2client www.example.com
```

# Note
If you want to decrypt TLS packet and to analyze HTTP/2 frames, you should better modify SSLKEYLOGFILE. And set wireshark key settings. Preferences -> Protocol -> TLS -> 「(Pre)-Master-Secret log filename」
```
$ grep SSLKEYLOGFILE src/Definitions.h 
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
```
