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

// この関数はHEADERSフレーム情報が取得できているものとして呼び出すこと
// Hpack表現に応じてポインタ加算が変わってくるので、全読み込みしておく必要がある。
int Hpack::readHpackHeaders(int payload_length, unsigned char* p){
	int key_index = 0;
	char firstbyte;

	// FIXME:
	while(1){
		firstbyte = p[0];
		printf("Leading text" BYTE_TO_BINARY_PATTERN "\n", BYTE_TO_BINARY(firstbyte));

		if( firstbyte & 0x80 ){
			// 1ビット目が1の場合には「Indexed Header Field Representation」
			// https://tools.ietf.org/html/rfc7541#section-6.1

			// 2ビット目から8ビット目がIndex値となるので取得する。
			key_index = firstbyte & (0x40|0x20|0x10|0x08|0x04|0x02|0x01);
			printf("Indexed Header Field Representation: index=%d %s %s\n", key_index, static_table_def[key_index-1][0], static_table_def[key_index-1][1]);
			p++;
			payload_length--;
		} else if(firstbyte & 0x40){   
			// (1bit, 2bit) = (0, 1)の場合には、「Literal Header Field with Incremental Indexing」
			// https://tools.ietf.org/html/rfc7541#section-6.2.1
			printf("Literal Header Field with Incremental Indexing\n");
			// 下位6bitを取得して0かどうかをチェックする。
//			key_index = firstbyte & (0x20|0x10|0x08|0x04|0x02|0x01);
//			if(key_index == 0){
//			} else {
//			}
			//FIXME: 正しいオフセット分増加させる必要あり
			p++;
			payload_length--;

		} else if(firstbyte & 0x20){
			// (1bit, 2bit, 3bit)=(0,0,1)のケースは動的テーブル更新の場合
			// https://tools.ietf.org/html/rfc7541#section-6.3
			printf("Dynamic Table Size Update\n");
			p++;
			payload_length--;
		} else if(!(firstbyte & 0x10)){
			// (1bit, 2bit, 3bit, 4bit)=(0,0,0,0)の場合は、「Literal Header Field without Indexing」
			// https://tools.ietf.org/html/rfc7541#section-6.2.2
			//FIXME: 正しいオフセット分増加させる必要あり
			p++;
			payload_length--;
		} else if(!(firstbyte & 0x10)){
			// (1bit, 2bit, 3bit, 4bit)=(0,0,0,1)の場合は、「Literal Header Field Never Indexed」
			// https://tools.ietf.org/html/rfc7541#section-6.2.3
			printf("Literal Header Field Never Indexed\n");
			//FIXME: 正しいオフセット分増加させる必要あり
			p++;
			payload_length--;
		} else {
			// 存在しないはず
			printf("[ERROR] invaid Hpack Representation\n");
			//FIXME: 正しいオフセット分増加させる必要あり
			p++;
			payload_length--;
		}

		if(payload_length==0){
			break;
		}
	}
	return 0;
}
