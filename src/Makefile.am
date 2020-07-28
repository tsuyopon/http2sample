bin_PROGRAMS = http2server http2client

# http2server
http2server_SOURCES = StreamState.cc ConnectionState.cc DebugUtils.cc HuffmanCode.cc FrameProcessor.cc Hpack.cc http2server.cc
http2server_LDADD = -lssl -lcrypto
http2server_LDFLAGS = -std=c++17 -Wall -Wextra

# http2client
http2client_SOURCES = RequestUtil.cc StreamState.cc ConnectionState.cc DebugUtils.cc HuffmanCode.cc FrameProcessor.cc Hpack.cc http2client.cc
http2client_LDADD = -lssl -lm
http2client_LDFLAGS = -std=c++17 -Wall -Wextra
