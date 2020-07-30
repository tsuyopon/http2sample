#pragma once

#include<cstring>
#include<cmath>
#include<map>
#include<string>
#include<vector>

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

#define DYNAMIC_TABLE_OFFSET  61

// [RFC7541] Appendix A. Static Table Definition 
// https://tools.ietf.org/html/rfc7541#appendix-A
static const char static_table_def[DYNAMIC_TABLE_OFFSET][2][30] = {
	{":authority", "\0"},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"}, // 10
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charet", "\0"},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", "\0"},
	{"accept-ranges", "\0"},
	{"accept", "\0"},
	{"access-control-allow-origin", "\0"}, // 20
	{"age", "\0"},
	{"allow", "\0"},
	{"authorization", "\0"},
	{"cache-control", "\0"},
	{"content-disposition", "\0"},
	{"content-encoding", "\0"},
	{"content-language", "\0"},
	{"content-length", "\0"},
	{"content-location", "\0"},
	{"content-range", "\0"},  // 30
	{"content-type", "\0"},
	{"cookie", "\0"},
	{"date", "\0"},
	{"etag", "\0"},
	{"expect", "\0"},
	{"expires", "\0"},
	{"from", "\0"},
	{"host", "\0"},
	{"if-match", "\0"},
	{"if-modified-since", "\0"},  // 40
	{"if-none-match", "\0"},
	{"if-range", "\0"},
	{"if-unmodified-since", "\0"},
	{"last-modified", "\0"},
	{"link", "\0"},
	{"location", "\0"},
	{"max-forwards", "\0"},
	{"proxy-authenticate", "\0"},
	{"proxy-authorization", "\0"},
	{"range", "\0"}, // 50
	{"referer", "\0"},
	{"refresh", "\0"},
	{"retry-after", "\0"},
	{"server", "\0"},
	{"set-cookie", "\0"},
	{"strict-transport-security", "\0"},
	{"transfer-encoding", "\0"},
	{"user-agent", "\0"},
	{"vary", "\0"},
	{"via", "\0"}, // 60
	{"www-authenticate", "\0"}
};

// FIXME: scopeが広いのであとで修正
/*
 * 動的テーブルの構造は以下を参照のこと
 * Insertion Pointが先頭からで、途中で動的サイズの更新パケットがあるのも考慮してvectorを利用する。
 * keyとvalueは他とも重複しても構わないので、vectorを利用している(std::mapだけだと重複は許されない)
 *
 *  See: RFC7541 sec 2.3.3
 *
 *   <----------  Index Address Space ---------->
 *   <-- Static  Table -->  <-- Dynamic Table -->
 *   +---+-----------+---+  +---+-----------+---+
 *   | 1 |    ...    | s |  |s+1|    ...    |s+k|
 *   +---+-----------+---+  +---+-----------+---+
 *                          ^                   |
 *                          |                   V
 *                   Insertion Point      Dropping Point
 *
 *               Figure 1: Index Address Space
 */
static std::vector<std::map<std::string, std::string>> g_dynamic_table_;


class Hpack {
public:
	static int createHpack(const std::string header, const std::string value, unsigned char* &dst);
	static void decodeLiteralHeaderFieldRepresentation(unsigned char* &p, unsigned int *payload_length, int nbit_prefix, bool indexing);
	static int readHpackHeaders(unsigned int payload_length, unsigned char* p);
	static int decodeIntegerRepresentation(unsigned char* p, int nbit_prefix, unsigned int *read_bytes, unsigned int *value_length, bool *first_bit_set);
};
