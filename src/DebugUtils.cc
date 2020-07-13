#include "DebugUtils.h"

// wiresharkにHTTP/2としてTLSを解読させるためにrandomとmaster_secertを出力する。デバッグをしやすくするため。
void DebugUtils::createSslKeyLogFile(SSL *ssl, const char* keylogfile){
    unsigned char buf_raw_r[SSL3_RANDOM_SIZE];
    unsigned char buf_raw_m[SSL_MAX_MASTER_KEY_LENGTH];
    unsigned char buf_client_random[SSL3_RANDOM_SIZE*2+1];
    unsigned char buf_master_key[SSL_MAX_MASTER_KEY_LENGTH*2+1];
    ssize_t res;

    FILE *outputfile;         // 出力ストリーム
    outputfile = fopen(keylogfile, "a");
	if(outputfile == NULL){
		printf("DebugUtils::createSslKeyLogFile fopen error. Don't write SSLKEYLOGFILE.");
		return;
	}

    size_t ssl_client_r = SSL_get_client_random(ssl, buf_raw_r, SSL3_RANDOM_SIZE);
    res = DebugUtils::to_hex(buf_client_random, sizeof(buf_client_random), buf_raw_r, ssl_client_r);
    res = fprintf(outputfile, "CLIENT_RANDOM %s ", buf_client_random);

    size_t ssl_client_m = SSL_SESSION_get_master_key(SSL_get_session(ssl), buf_raw_m, SSL_MAX_MASTER_KEY_LENGTH);
    res = DebugUtils::to_hex(buf_master_key, sizeof(buf_master_key), buf_raw_m, ssl_client_m);
    res = fprintf(outputfile, "%s\n", buf_master_key);

    fclose(outputfile);          // ファイルをクローズ(閉じる)
}

ssize_t DebugUtils::to_hex(unsigned char *dst, size_t dst_len, unsigned char *src, size_t src_len) {
	ssize_t wr = 0;
	for (size_t i = 0; i < src_len; i++) {
//		printf("%02X", src[i]);
		int w = snprintf((char *) dst + wr, dst_len - (size_t) wr, "%02x", src[i]);
		if (w <= 0)
			return -1;
		wr += (ssize_t) w;
	}
//	printf("\n");
	return wr;
}
