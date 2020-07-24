all: clean client server

server: StreamState.o ConnectionState.o DebugUtils.o HuffmanCode.o FrameProcessor.o Hpack.o http2server.o
	g++ -g $+ -o http2server -lssl -lcrypto -std=c++17 -Wall -Wextra 

client: StreamState.o ConnectionState.o RequestUtil.o HuffmanCode.o FrameProcessor.o DebugUtils.o Hpack.o http2client.o
	g++ -g $+ -o http2client -lssl -lm -std=c++17 -Wall -Wextra

%.o: %.cc
	g++ -O -c $< -o $@ -std=c++17 -Wall -Wextra

cscope:
	-rm -f cscope.out
	cscope -R -b

clean:
	rm -rf *.o a.out main http2client http2server *.dSYM *.gch


test0:
	./http2client -u https://localhost/

test1:
	./http2client -u https://www.yahoo.co.jp/

test2:
	./http2client -u https://www.youtube.com/

