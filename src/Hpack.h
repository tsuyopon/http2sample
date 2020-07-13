#ifndef HPACK_H
#define HPACK_H

#include<string>
#include<cstring>
#include<cmath>

// see: https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

// [RFC7541] Appendix A. Static Table Definition 
// https://tools.ietf.org/html/rfc7541#appendix-A
const char static_table_def[61][2][30] = {
	{":authority", NULL},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charet", NULL},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", NULL},
	{"accept-ranges", NULL},
	{"accept", NULL},
	{"access-control-allow-origin", NULL},
	{"age", NULL},
	{"allow", NULL},
	{"authorization", NULL},
	{"cache-control", NULL},
	{"content-disposition", NULL},
	{"content-encoding", NULL},
	{"content-language", NULL},
	{"content-length", NULL},
	{"content-location", NULL},
	{"content-range", NULL},
	{"content-type", NULL},
	{"cookie", NULL},
	{"date", NULL},
	{"etag", NULL},
	{"expect", NULL},
	{"expires", NULL},
	{"from", NULL},
	{"host", NULL},
	{"if-match", NULL},
	{"if-modified-since", NULL},
	{"if-none-match", NULL},
	{"if-range", NULL},
	{"if-unmodified-since", NULL},
	{"last-modified", NULL},
	{"link", NULL},
	{"location", NULL},
	{"max-forwards", NULL},
	{"proxy-authenticate", NULL},
	{"proxy-authorization", NULL},
	{"range", NULL},
	{"referer", NULL},
	{"refresh", NULL},
	{"retry-after", NULL},
	{"server", NULL},
	{"set-cookie", NULL},
	{"strict-transport-security", NULL},
	{"transfer-encoding", NULL},
	{"user-agent", NULL},
	{"vary", NULL},
	{"via", NULL},
	{"www-authenticate", NULL}
};

class Hpack {
public:
	static int createHpack(const std::string header, const std::string value, unsigned char* &dst);
	static int readHpackHeaders(int payload_length, unsigned char* p);
	static int decodeIntegerRepresentation(unsigned char* p, int nbit_prefix, unsigned int *read_bytes, unsigned int *value_length, bool *first_bit_set);
};

#endif  // HPACK_H
