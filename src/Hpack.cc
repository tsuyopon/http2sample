#include "Hpack.h"

// HPACKの簡単なデータを作成する。
// ここで対応しているのは、以下のパターンのみ。
// しかし、headerまたはvalueが127文字を超過した際のパケットの整数表現に対応できていないという非常に簡易なもの
// https://tools.ietf.org/html/rfc7541#section-6.2.2
int Hpack::createHpack(const std::string header, const std::string value, unsigned char* &dst){
    unsigned char *hpack;
    hpack = static_cast<unsigned char*>(std::malloc( 1 + 1 + header.length() + 1 + value.length()));
    hpack[0] = 0;
    hpack[1] = header.length();
    memcpy(hpack+2, header.c_str(), header.length());
    hpack[2+header.length()] = value.length();
    memcpy(hpack+2+header.length()+1, value.c_str(), value.length());

//    printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", hpack[0], hpack[1],hpack[2],hpack[3],hpack[4],hpack[5],hpack[6],hpack[7],hpack[8]);
    dst = hpack;
//    printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", dst[0], dst[1],dst[2],dst[3],dst[4],dst[5],dst[6],dst[7],dst[8]);
    return 1 + 1 + header.length() + 1 + value.length();
}
