all: HuffmanCode.o FrameProcessor.o DebugUtils.o Hpack.o main.o
	g++ $+ -o http2client -lssl -lm -std=c++17 -Wall -Wextra

%.o: %.cc
	g++ -O -c $< -o $@ -std=c++17 -Wall -Wextra

clean:
	rm -f *.o a.out main http2client
