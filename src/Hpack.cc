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
	unsigned char firstbyte;

	// FIXME:
	while(1){
		firstbyte = p[0];
		printf("Leading text: " BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(firstbyte), firstbyte);

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
			unsigned int read_bytes, value_length;
			bool first_bit_set;
			if(decodeIntegerRepresentation(p, 6 /*nbit_prefix*/, &read_bytes, &value_length, &first_bit_set) == 1){  // 整数表現ではない
				// See: https://tools.ietf.org/html/rfc7541#section-6.2.1   Figure7
				// ヘッダ名とヘッダ値を取得する
				p = p + read_bytes;
				payload_length = payload_length - read_bytes;

				printf("Header Name = xxxxx\n");  // FIXME: hufman encoding
				if(decodeIntegerRepresentation(p, 7 /*nbit_prefix*/, &read_bytes, &value_length, &first_bit_set) == 1){
					printf("[ERROR] Could Not get Header Length\n");
				} else {
					if(first_bit_set) printf("\tHufman encoding flag is set\n");
					p = p + read_bytes;
					p = p + value_length;
					payload_length = payload_length - read_bytes - value_length;
				}
				
			} else { // 整数表現
				// See: https://tools.ietf.org/html/rfc7541#section-6.2.1   Figure6
				// ヘッダ名はindexから取得して、ヘッダ値を取得する
				printf("Header Name = %s\n", static_table_def[value_length-1][0]);
				p = p + read_bytes;
				payload_length = payload_length - read_bytes;
			}

			// ヘッダ値の長さを取得する

			if(decodeIntegerRepresentation(p, 7 /*nbit_prefix*/, &read_bytes, &value_length, &first_bit_set) == 1){
				printf("[ERROR] Could Not get Header Length\n");
			} else {
				if(first_bit_set) printf("\tHufman encoding flag is set\n");
				// FIXME: ハフマン符号の解釈
				p = p + read_bytes;
				p = p + value_length;
				payload_length = payload_length - read_bytes - value_length;
			}

		} else if(firstbyte & 0x20){
			// (1bit, 2bit, 3bit)=(0,0,1)のケースは動的テーブル更新の場合
			// https://tools.ietf.org/html/rfc7541#section-6.3
			printf("Dynamic Table Size Update\n");
			// FIXME: 更新させる
			p++;
			payload_length--;
		} else if(!(firstbyte & 0x10)){
			// (1bit, 2bit, 3bit, 4bit)=(0,0,0,0)の場合は、「Literal Header Field without Indexing」
			// https://tools.ietf.org/html/rfc7541#section-6.2.2

			// 下位4bitを取得して0かどうかでHpack表現がわかれます。
			key_index = firstbyte & (0x08|0x04|0x02|0x01);
			printf("Literal Header Field without Indexing. index=%d\n", key_index);

			if(key_index == 0){

				// ヘッダ長の取得
				int name_length;
				name_length = p[1];

				// ヘッダ長分のoctetを取得
				char* name;
				name = static_cast<char*>(malloc(name_length+1));
				memcpy(name, &(p[2]), name_length);
				memcpy(&(name[name_length]), &(p[2+name_length]), '\0');
				printf("Header Name = %s\n", name);

			} else if(key_index == 15){  // 下位4bitがすべて1の場合
				unsigned int real_key_index = 0;
				real_key_index = p[1] + 15;
				printf("RealIndex=%d %s %s\n", real_key_index, static_table_def[real_key_index-1][0], static_table_def[real_key_index-1][1]);

				unsigned int value_length = 0;
				value_length = p[2];   //  FIXME: do not consider hufman encoding
				printf("length %d, %d\n", value_length, p[2]);

				char* value;
				value = static_cast<char*>(malloc(value_length+1));
				memcpy(value, &(p[3]), value_length);
				memcpy(&(value[value_length]), &(p[2+value_length]), '\0');
				printf("Header Name = %s\n", value);

			} else {
			}

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
			//FIXME: エラーにした方が正しいかも
			p++;
			payload_length--;
		}

		// 処理するパケットがなくなればbreakする
		if(payload_length==0){
			break;
		}

		// 0よりも小さい場合にはパケット処理の帳尻があっていないので、何かプログラムミスしている可能性が高いと思われる。
		if(payload_length<0){
			printf("[ERROR] maybe caused by program miss");
			break;
		}
	}
	return 0;
}


//------------------------------------------------------------
// 1byte目だけでは整数表現を表せない場合に(2byte目以上も使う場合)、整数表現された値と整数表現の値を形成するために読み込みしたbyte数を返す関数
//
// take1(input): 読み込み開始をする先頭バッファの指定
// take2(input): 最初の1byte目で表現されている数
// take3(output): read_bytes: pから整数表現を解釈するために読み込んだバイト数
// take4(output): value_length: 整数表現で表される値を表す。
//
// 以下のようにvalueのみが文字列で指定される場合には、この関数は1度だけ呼ばれる。
// +---+---+---+---+---+---+---+---+
// | 0 | 0 | 0 | 1 |  Index (4+)   |
// +---+---+-----------------------+
// | H |     Value Length (7+)     |
// +---+---------------------------+
// | Value String (Length octets)  |
// +-------------------------------+
//
// Index Header表現の場合にもIndexは7+なので、この7bitが全て1ならば、この関数がその後の整数表現を取得するために1度呼ばれる。
// +---+---+---+---+---+---+---+---+
// | 1 |        Index (7+)         |
// +---+---------------------------+
//
// 以下のようにキー名も文字列で指定される場合には、この関数は2度呼ばれる。
// +---+---+---+---+---+---+---+---+
// | 0 | 1 |           0           |
// +---+---+-----------------------+
// | H |     Name Length (7+)      |
// +---+---------------------------+
// |  Name String (Length octets)  |
// +---+---------------------------+
// | H |     Value Length (7+)     |
// +---+---------------------------+
// | Value String (Length octets)  |
// +-------------------------------+
//
// decodeアルゴリズムは以下に準ずる
// https://tools.ietf.org/html/rfc7541#section-5.1
//------------------------------------------------------------
int Hpack::decodeIntegerRepresentation(unsigned char* p, int nbit_prefix, unsigned int *read_bytes, unsigned int *value_length, bool *first_bit_set){

	unsigned char next_octet;
	unsigned int integer = 0;
	unsigned int m = 0;
	unsigned int flags = 0;

	next_octet = p[0];
	if(nbit_prefix >= 1) flags |= 0x01;
	if(nbit_prefix >= 2) flags |= 0x02;
	if(nbit_prefix >= 3) flags |= 0x04;
	if(nbit_prefix >= 4) flags |= 0x08;
	if(nbit_prefix >= 5) flags |= 0x10;
	if(nbit_prefix >= 6) flags |= 0x20;
	if(nbit_prefix >= 7) flags |= 0x40;

	// 最初の1byte目の指定されたnbit_prefixが全て0である場合(整数表現ではない場合)
//	printf("Leading text: " BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(next_octet), next_octet);
	integer = next_octet & flags;
	if( integer == 0 ){
		return 1;   // 整数表現ではない
	}

	*first_bit_set = next_octet & 0x80;

	// 最初の1byte目の指定されたnbit_prefixで整数表現が完結している。
	if( integer < pow(2, nbit_prefix) -1 ){
		*read_bytes = 1;     // always return 1
		*value_length = integer;
//		printf("read_bytes = %d, value_length = %d\n", *read_bytes, *value_length);
		return 0;
	}

	// 1byte目のチェックが終わっているのでcountとポインタ増加を1進める
	unsigned int count = 1;
	p++;

	// 2byte目以降を処理する
	do {
		next_octet = p[0];
		printf("Leading text: " BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(next_octet), next_octet);
		integer = integer + ((next_octet & 127) * pow(2,m));  // 下位7bitだけ計算対象として、2^mを加算する
		printf("%02x, integer=%d, m=%d \n", next_octet, integer, m);
		m = m + 7;                          // 先頭ビットは計算対象外
		p++;                                // 次のポインタを処理するために追加
		count++;                            // 何バイト処理したか
	} while( ((next_octet & 128) == 128) );  // 先頭ビットが立っていたら継続

	*read_bytes = count;
	*value_length = integer;
//	printf("read_bytes = %d, value_length = %d\n", *read_bytes, *value_length);
	return 0;

}
