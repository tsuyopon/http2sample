all: http2client

http2client: RequestUtil.o HuffmanCode.o FrameProcessor.o DebugUtils.o Hpack.o http2client.o
	g++ $+ -o http2client -lssl -lm -std=c++17 -Wall -Wextra

%.o: %.cc
	g++ -O -c $< -o $@ -std=c++17 -Wall -Wextra

cscope:
	-rm -f cscope.out
	cscope -R -b

clean:
	rm -f *.o a.out main http2client
