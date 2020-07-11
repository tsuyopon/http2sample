#ifndef HPACK_H
#define HPACK_H

#include<string>

class Hpack {
public:
	static int createHpack(const std::string header, const std::string value, unsigned char* &dst);
};

#endif  // HPACK_H
