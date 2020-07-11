#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

class DebugUtils {
public:
	static void createSslKeyLogFile(SSL *ssl, const char* keylogfile);

private:
	static ssize_t to_hex(unsigned char *dst, size_t dst_len, unsigned char *src, size_t src_len);
};

#endif  // DEBUG_UTILS_H
