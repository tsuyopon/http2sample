#include "Hpack.h"
#include "HuffmanCode.h"

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

//	  printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", hpack[0], hpack[1],hpack[2],hpack[3],hpack[4],hpack[5],hpack[6],hpack[7],hpack[8]);
	dst = hpack;
//	  printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X\n", dst[0], dst[1],dst[2],dst[3],dst[4],dst[5],dst[6],dst[7],dst[8]);
	return 1 + 1 + header.length() + 1 + value.length();
}

// FIXME: あとでいどう
void printStringFromHpack(unsigned char* p, unsigned int value_length){
	printf("\tParse String: ");
	while(value_length){
		printf("%c", p[0]);
		p++;
		value_length--;
	}
	printf("\n");
}

/*------------------------------------------------------------
 * 
 * Literal Header Field Representationの共通処理を行う。
 * 
 * 以下の3つの"Literal Header Field Represetation"に該当するケースでは非常に処理が類似している。
 *    Literal Header Field with Incremental Indexing
 *    Literal Header Field without Indexing
 *    Literal Header Field Never Indexed
 *
 * 上記3つは以下の共通ロジックとなっている。
 *    先頭にindex表現があれば、次にValue Lengthの整数表現、その後整数表現分のValueが来る
 *    先頭にindex表現がなければ、次にName Lengthの整数表現、整数表現分のNameの値、Value Lengthの整数表現、整数表現分のValueが来る
 * 
 ------------------------------------------------------------*/
void Hpack::decodeLiteralHeaderFieldRepresentation(unsigned char* &p, unsigned int *payload_length, int nbit_prefix){
	unsigned int read_bytes = 0;
	unsigned int value_length = 0;
	bool first_bit_set;
	if(decodeIntegerRepresentation(p, nbit_prefix, &read_bytes, &value_length, &first_bit_set) == 1){  // 整数表現ではない
		// See: https://tools.ietf.org/html/rfc7541#section-6.2.1   Figure7
		// ヘッダ名とヘッダ値を取得する
		p = p + 1;
		*payload_length = *payload_length - 1;
		printf("\tHeader Name = xxxxx\n");	// FIXME: hufman encoding
		if(decodeIntegerRepresentation(p, 7 /*nbit_prefix*/, &read_bytes, &value_length, &first_bit_set) == 1){
			printf("[ERROR] Could Not get Header Length\n");
		} else {
			printf("\tpayload_length=%d, read_values=%d, value_length=%d\n", *payload_length, read_bytes, value_length);
			p = p + read_bytes;

			if(first_bit_set) {
				printf("\tHeaderName: Hufman encoding flag IS set\n");
				HuffmanCode::decodeHuffman(p, value_length);
			} else {
				printf("\tHeaderName: Hufman encoding flag IS NOT set\n");
				printStringFromHpack(p, value_length);
			}
			p = p + value_length;
			*payload_length = *payload_length - read_bytes - value_length;
		}
		
	} else { // 整数表現
		// See: https://tools.ietf.org/html/rfc7541#section-6.2.1   Figure6
		// ヘッダ名はindexから取得して、ヘッダ値を取得する
		printf("\tHeader Name = %s\n", static_table_def[value_length-1][0]);
		p = p + read_bytes;
		*payload_length = *payload_length - read_bytes;
	}

	// ヘッダ値の長さを取得する

	if(decodeIntegerRepresentation(p, 7 /*nbit_prefix*/, &read_bytes, &value_length, &first_bit_set) == 1){
		printf("[ERROR] Could Not get Header Length\n");
	} else {
		p = p + read_bytes;
		if(first_bit_set) {
			printf("\tHeaderValue: Hufman encoding flag IS set\n");
			HuffmanCode::decodeHuffman(p, value_length);
		} else {
			printf("\tHeaderValue: Hufman encoding flag IS NOT set\n");
			printStringFromHpack(p, value_length);
		}
		p = p + value_length;
		*payload_length = *payload_length - read_bytes - value_length;
	}
}

/*------------------------------------------------------------
 * 
 * 先頭ビットprefixをチェックして、Hpack表現の判定を行い、必要なデータ情報を読み込む
 * (Hpack表現に応じてポインタ加算が変わってくるので、この関数を呼び出す際には全読み込みしておく必要がある)
 *
 * whileでHEADER区切りごとに処理が行われます。以下の表現のチェックを行う。
 *   1. Indexed Header Field Representation
 *   2. Literal Header Field with Incremental Indexing
 *   3. Dynamic Table Size Update
 *   4. Literal Header Field without Indexing
 *   5. Literal Header Field Never Indexed
 * 
 ------------------------------------------------------------*/
int Hpack::readHpackHeaders(unsigned int payload_length, unsigned char* p){
	int key_index = 0;
	unsigned char firstbyte;

	// FIXME: Huffman Encodingには未対応
	while(1){
		firstbyte = p[0];
//		printf("Leading text: " BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(firstbyte), firstbyte);

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
			decodeLiteralHeaderFieldRepresentation(p, &payload_length, 6 /*nbit_prefix*/);
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

			decodeLiteralHeaderFieldRepresentation(p, &payload_length, 4 /*nbit_prefix*/);

		} else if(!(firstbyte & 0x10)){
			// (1bit, 2bit, 3bit, 4bit)=(0,0,0,1)の場合は、「Literal Header Field Never Indexed」
			// https://tools.ietf.org/html/rfc7541#section-6.2.3
			printf("Literal Header Field Never Indexed\n");
			// TODO: 動作確認未実施
			decodeLiteralHeaderFieldRepresentation(p, &payload_length, 4 /*nbit_prefix*/);
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

		printf("\n");
	}
	return 0;
}

/*------------------------------------------------------------
 * 
 * nbit_prefixを与えてHpackの整数表現されたoctet列を解析し、その値、読み込みしたoctet数、先頭ビットが立っているかどうかを判定する。
 *
 * @param p 読み込み開始をする先頭バッファアドレス
 * @param nbit_prefix  1octet目で表される整数表現の長さ
 * @param read_bytes 読み込んだバイト数の結果(output)
 * @param value_length 整数表現で指定された値の結果(output)
 * @param first_bit_set 渡されたpの1byte目の先頭ビットが立っているかどうかを表す。(ハフマンエンコーディングの判定に利用する)
 *
 * @return
 *      指定されたnbit_prefixが全て0で満たされていた場合、整数表現は存在しない。=> 0を応答する。
 *      指定されたnbit_prefixが全て0以外の場合には、整数表現が存在する。        => 1を応答する。
 *
 * @detail 
 *
 * [使い方]
 *
 * 以下のパケットを解析する場合には、
 *   最初の1octet目の整数表現を取得するために1度目を呼ぶ。
 *      nbit_prefixは4を指定指定し、
 *      read_bytesは何バイト読み込まれたのかを返す。
 *      value_lengthは整数表現としての値を返す。
 *      first_bit_setはValue LengthやName Lengthの整数表現を取得しようとした際のHufman Encoding判定に利用する。この場合はHufman Encodingを識別するビットは無いので、意味をなさない
 *   その後、Value Lengthの整数表現を取得するために2度目を呼ぶ
 *      nbit_prefixは7を指定指定し、
 *      read_bytesは何バイト読み込まれたのかを返す。
 *      value_lengthは整数表現としての値を返す。
 *      first_bit_setはValue LengthやName Lengthの整数表現を取得しようとした際のHufman Encoding判定に利用する。この場合はHufman Encodingを識別するビットHが存在するので、判定に利用できる。
 *
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 0 | 1 |  Index (4+)   |
 * +---+---+-----------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * | Value String (Length octets)  |
 * +-------------------------------+
 *
 ------------------------------------------------------------*/
int Hpack::decodeIntegerRepresentation(unsigned char* p, int nbit_prefix, unsigned int *read_bytes, unsigned int *value_length, bool *first_bit_set){

	unsigned char next_octet;
	unsigned int integer = 0;
	unsigned int m = 0;
	unsigned int flags = 0;

	next_octet = p[0];

	// 1octet目の先頭ビットが立っていればfirst_bit_setがtrueとなる。
	*first_bit_set = next_octet & 0x80;

	// nbit_prefixに指定された値が1から7ビットに応じて必要なビットフラグをセットする
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
		*read_bytes = 1;
		*value_length = 0;
		return 1;   // 整数表現ではない
	}

	// See HpackDecode Algorithm
	// https://tools.ietf.org/html/rfc7541#section-5.1

	// 最初の1byte目の指定されたnbit_prefixで整数表現が完結している。
	if( integer < pow(2, nbit_prefix) -1 ){
		*read_bytes = 1;     // always return 1
		*value_length = integer;
//		printf("read_bytes = %d, value_length = %d\n", *read_bytes, *value_length);
		return 0;
	}

	// 1byte目のチェックがこの時点で終わっているのでcountとポインタ増加を1進める
	unsigned int count = 1;
	p++;

	// 2byte目以降を処理する
	do {
		next_octet = p[0];
//		printf("Leading text: " BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(next_octet), next_octet);
		integer = integer + ((next_octet & 127) * pow(2,m));  // 下位7bitだけ計算対象として、2^mを加算する
		printf("%02x, integer=%d, m=%d \n", next_octet, integer, m);
		m = m + 7;                           // 先頭ビットは計算対象外
		p++;                                 // 次のポインタを処理するために追加
		count++;                             // 何バイト処理したか
	} while( ((next_octet & 128) == 128) );  // 先頭ビットが立っていたら継続

	*read_bytes = count;
	*value_length = integer;
//	printf("read_bytes = %d, value_length = %d\n", *read_bytes, *value_length);
	return 0;

}
