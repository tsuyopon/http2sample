...This repository is UNDER CONSTRUCTING...

# http2sample
This is test sample for http2 client and http2 server.

There are too many limitations about this source code.
- can access only https://\<domain\>/ at 1 times,   can not specify any entrypoint.
- completly blocking access
- and a lot...

# Requrement
- GCC 5 or lator (std=c++17 support compiler)
  - https://gcc.gnu.org/projects/cxx-status.html#cxx17
- require openssl-1.1.0+ to compile this source code.

# Compile (handy execute mode)
you can build using handy mode
```
$ cd src/
$ make -f Makefile.handy
```

# Setup (Install using autotools)
autotools is needed. you can install this tool by typing below command.
```
//Debian or Ubuntu
$ sudo apt-get install autoconf automake libtool autoconf-doc libtool-doc

// Mac(homebrew)
$ sudo brew install automake autoconf

// Mac(port)
$ sudo port install automake autoconf
```

type here to install
```
$ ./autogen.sh 
$ ./configure
$ make
$ make install
```

# Execute

### Client Program
you can specify target url using u option.
```
$ ./http2client -u https://example.com/hoge/fuga/piyo
```

you can specify request header using H option.
```
$ ./http2client -u https://example.com/hoge/fuga/piyo -H 'hoge:fuga'
```


### Server Program
kick http2 server program
```
$ sudo ./http2server
```

http2client program can connect to http2server.
```
(example)
$ ./http2client -u https://localhost/ -H 'hoge:fuga'
```

# Note
If you want to decrypt TLS packet and to analyze HTTP/2 frames, you should better modify SSLKEYLOGFILE. And set wireshark key settings. Preferences -> Protocol -> TLS -> 「(Pre)-Master-Secret log filename」
```
$ grep SSLKEYLOGFILE src/Definitions.h 
#define SSLKEYLOGFILE "/Users/tsuyoshi/Desktop/tls_key.log"
```
