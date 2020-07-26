#include "HuffmanCode.h"
#include "Hpack.h"
#include <iostream>

namespace {

struct huffman_code {
  uint32_t  len;
  uint32_t  bits;
  char string;
};

// https://tools.ietf.org/html/rfc7541#appendix-B
// FIXME: stdio.hをincludeするとこの配列がなぜか重複定義になる
huffman_code huffman_code_table[] = {
	{13, 0b1111111111000, '\0'},                  // 0
	{23, 0b11111111111111111011000, '\0'},        // 1
	{28, 0b1111111111111111111111100010, '\0'},   // 2
	{28, 0b1111111111111111111111100011, '\0'},   // 3
	{28, 0b1111111111111111111111100100, '\0'},   // 4
	{28, 0b1111111111111111111111100101, '\0'},   // 5
	{28, 0b1111111111111111111111100110, '\0'},   // 6
	{28, 0b1111111111111111111111100111, '\0'},   // 7
	{28, 0b1111111111111111111111101000, '\0'},   // 8
	{24, 0b111111111111111111101010, '\0'},       // 9
	{30, 0b111111111111111111111111111100, '\0'}, // 10
	{28, 0b1111111111111111111111101001, '\0'},   // 11
	{28, 0b1111111111111111111111101010, '\0'},   // 12
	{30, 0b111111111111111111111111111101, '\0'}, // 13
	{28, 0b1111111111111111111111101011, '\0'},   // 14
	{28, 0b1111111111111111111111101100, '\0'},   // 15
	{28, 0b1111111111111111111111101101, '\0'},   // 16
	{28, 0b1111111111111111111111101110, '\0'},   // 17
	{28, 0b1111111111111111111111101111, '\0'},   // 18
	{28, 0b1111111111111111111111110000, '\0'},   // 19
	{28, 0b1111111111111111111111110001, '\0'},   // 20
	{28, 0b1111111111111111111111110010, '\0'},   // 21
	{30, 0b111111111111111111111111111110, '\0'}, // 22
	{28, 0b1111111111111111111111110011, '\0'},   // 23
	{28, 0b1111111111111111111111110100, '\0'},   // 24
	{28, 0b1111111111111111111111110101, '\0'},   // 25
	{28, 0b1111111111111111111111110110, '\0'},   // 26
	{28, 0b1111111111111111111111110111, '\0'},   // 27
	{28, 0b1111111111111111111111111000, '\0'},   // 28
	{28, 0b1111111111111111111111111001, '\0'},   // 29
	{28, 0b1111111111111111111111111010, '\0'},   // 30
	{28, 0b1111111111111111111111111011, '\0'},   // 31
	{6, 0b010100, ' '},                          // 32
	{10, 0b1111111000, '!'},                     // 33
	{10, 0b1111111001, '"'},                     // 34
	{12, 0b111111111010, '#'},                   // 35
	{13, 0b1111111111001, '$'},                  // 36
	{6, 0b010101, '%'},                          // 37
	{8, 0b11111000, '&'},                        // 38
	{11, 0b11111111010, '\''},                   // 39
	{10, 0b1111111010, '('},                     // 40
	{10, 0b1111111011, ')'},                     // 41
	{8, 0b11111001, '*'},                        // 42
	{11, 0b11111111011, '+'},                    // 43
	{8, 0b11111010, ','},                        // 44
	{6, 0b010110, '-'},                          // 45
	{6, 0b010111, '.'},                          // 46
	{6, 0b011000, '/'},                          // 47
	{5, 0b00000, '0'},                           // 48
	{5, 0b00001, '1'},                           // 49
	{5, 0b00010, '2'},                           // 50
	{6, 0b011001, '3'},                          // 51
	{6, 0b011010, '4'},                          // 52
	{6, 0b011011, '5'},                          // 53
	{6, 0b011100, '6'},                          // 54
	{6, 0b011101, '7'},                          // 55
	{6, 0b011110, '8'},                          // 56
	{6, 0b011111, '9'},                          // 57
	{7, 0b1011100, ':'},                         // 58
	{8, 0b11111011, ';'},                        // 59
	{15, 0b111111111111100, '<'},                // 60
	{6, 0b100000, '='},                          // 61
	{12, 0b111111111011, '>'},                   // 62
	{10, 0b1111111100, '?'},                     // 63
	{13, 0b1111111111010, '@'},                  // 64
	{6, 0b100001, 'A'},                          // 65
	{7, 0b1011101, 'B'},                         // 66
	{7, 0b1011110, 'C'},                         // 67
	{7, 0b1011111, 'D'},                         // 68
	{7, 0b1100000, 'E'},                         // 69
	{7, 0b1100001, 'F'},                         // 70
	{7, 0b1100010, 'G'},                         // 71
	{7, 0b1100011, 'H'},                         // 72
	{7, 0b1100100, 'I'},                         // 73
	{7, 0b1100101, 'J'},                         // 74
	{7, 0b1100110, 'K'},                         // 75
	{7, 0b1100111, 'L'},                         // 76
	{7, 0b1101000, 'M'},                         // 77
	{7, 0b1101001, 'N'},                         // 78
	{7, 0b1101010, 'O'},                         // 79
	{7, 0b1101011, 'P'},                         // 80
	{7, 0b1101100, 'Q'},                         // 81
	{7, 0b1101101, 'R'},                         // 82
	{7, 0b1101110, 'S'},                         // 83
	{7, 0b1101111, 'T'},                         // 84
	{7, 0b1110000, 'U'},                         // 85
	{7, 0b1110001, 'V'},                         // 86
	{7, 0b1110010, 'W'},                         // 87
	{8, 0b11111100, 'X'},                        // 88
	{7, 0b1110011, 'Y'},                         // 89
	{8, 0b11111101, 'Z'},                        // 90
	{13, 0b1111111111011, '['},                  // 91
	{19, 0b1111111111111110000, '\\'},           // 92    // FIXME: 要確認
	{13, 0b1111111111100, ']'},                  // 93
	{14, 0b11111111111100, '^'},                 // 94
	{6, 0b100010, '_'},                          // 95
	{15, 0b111111111111101, '`'},                // 96
	{5, 0b00011, 'a'},                           // 97
	{6, 0b100011, 'b'},                          // 98
	{5, 0b00100, 'c'},                           // 99
	{6, 0b100100, 'd'},                          // 100
	{5, 0b00101, 'e'},                           // 101
	{6, 0b100101, 'f'},                          // 102
	{6, 0b100110, 'g'},                          // 103
	{6, 0b100111, 'h'},                          // 104
	{5, 0b00110, 'i'},                           // 105
	{7, 0b1110100, 'j'},                         // 106
	{7, 0b1110101, 'k'},                         // 107
	{6, 0b101000, 'l'},                          // 108
	{6, 0b101001, 'm'},                          // 109
	{6, 0b101010, 'n'},                          // 110
	{5, 0b00111, 'o'},                           // 111
	{6, 0b101011, 'p'},                          // 112
	{7, 0b1110110, 'q'},                         // 113
	{6, 0b101100, 'r'},                          // 114
	{5, 0b01000, 's'},                           // 115
	{5, 0b01001, 't'},                           // 116
	{6, 0b101101, 'u'},                          // 117
	{7, 0b1110111, 'v'},                         // 118
	{7, 0b1111000, 'w'},                         // 119
	{7, 0b1111001, 'x'},                         // 120
	{7, 0b1111010, 'y'},                         // 121
	{7, 0b1111011, 'z'},                         // 122
	{15, 0b111111111111110, '{'},                // 123
	{11, 0b11111111100, '|'},                    // 124
	{14, 0b11111111111101, '}'},                 // 125
	{13, 0b1111111111101, '~'},                  // 126
	{28, 0b1111111111111111111111111100, '\0'},   // 127
	{20, 0b11111111111111100110, '\0'},           // 128
	{22, 0b1111111111111111010010, '\0'},         // 129
	{20, 0b11111111111111100111, '\0'},           // 130
	{20, 0b11111111111111101000, '\0'},           // 131
	{22, 0b1111111111111111010011, '\0'},         // 132
	{22, 0b1111111111111111010100, '\0'},         // 133
	{22, 0b1111111111111111010101, '\0'},         // 134
	{23, 0b11111111111111111011001, '\0'},        // 135
	{22, 0b1111111111111111010110, '\0'},         // 136
	{23, 0b11111111111111111011010, '\0'},        // 137
	{23, 0b11111111111111111011011, '\0'},        // 138
	{23, 0b11111111111111111011100, '\0'},        // 139
	{23, 0b11111111111111111011101, '\0'},        // 140
	{23, 0b11111111111111111011110, '\0'},        // 141
	{24, 0b111111111111111111101011, '\0'},       // 142
	{23, 0b11111111111111111011111, '\0'},        // 143
	{24, 0b111111111111111111101100, '\0'},       // 144
	{24, 0b111111111111111111101101, '\0'},       // 145
	{22, 0b1111111111111111010111, '\0'},         // 146
	{23, 0b11111111111111111100000, '\0'},        // 147
	{24, 0b111111111111111111101110, '\0'},       // 148
	{23, 0b11111111111111111100001, '\0'},        // 149
	{23, 0b11111111111111111100010, '\0'},        // 150
	{23, 0b11111111111111111100011, '\0'},        // 151
	{23, 0b11111111111111111100100, '\0'},        // 152
	{21, 0b111111111111111011100, '\0'},          // 153
	{22, 0b1111111111111111011000, '\0'},         // 154
	{23, 0b11111111111111111100101, '\0'},        // 155
	{22, 0b1111111111111111011001, '\0'},         // 156
	{23, 0b11111111111111111100110, '\0'},        // 157
	{23, 0b11111111111111111100111, '\0'},        // 158
	{24, 0b111111111111111111101111, '\0'},       // 159
	{22, 0b1111111111111111011010, '\0'},         // 160
	{21, 0b111111111111111011101, '\0'},          // 161
	{20, 0b11111111111111101001, '\0'},           // 162
	{22, 0b1111111111111111011011, '\0'},         // 163
	{22, 0b1111111111111111011100, '\0'},         // 164
	{23, 0b11111111111111111101000, '\0'},        // 165
	{23, 0b11111111111111111101001, '\0'},        // 166
	{21, 0b111111111111111011110, '\0'},          // 167
	{23, 0b11111111111111111101010, '\0'},        // 168
	{22, 0b1111111111111111011101, '\0'},         // 169
	{22, 0b1111111111111111011110, '\0'},         // 170
	{24, 0b111111111111111111110000, '\0'},       // 171
	{21, 0b111111111111111011111, '\0'},          // 172
	{22, 0b1111111111111111011111, '\0'},         // 173
	{23, 0b11111111111111111101011, '\0'},        // 174
	{23, 0b11111111111111111101100, '\0'},        // 175
	{21, 0b111111111111111100000, '\0'},          // 176
	{21, 0b111111111111111100001, '\0'},          // 177
	{22, 0b1111111111111111100000, '\0'},         // 178
	{21, 0b111111111111111100010, '\0'},          // 179
	{23, 0b11111111111111111101101, '\0'},        // 180
	{22, 0b1111111111111111100001, '\0'},         // 181
	{23, 0b11111111111111111101110, '\0'},        // 182
	{23, 0b11111111111111111101111, '\0'},        // 183
	{20, 0b11111111111111101010, '\0'},           // 184
	{22, 0b1111111111111111100010, '\0'},         // 185
	{22, 0b1111111111111111100011, '\0'},         // 186
	{22, 0b1111111111111111100100, '\0'},         // 187
	{23, 0b11111111111111111110000, '\0'},        // 188
	{22, 0b1111111111111111100101, '\0'},         // 189
	{22, 0b1111111111111111100110, '\0'},         // 190
	{23, 0b11111111111111111110001, '\0'},        // 191
	{26, 0b11111111111111111111100000, '\0'},     // 192
	{26, 0b11111111111111111111100001, '\0'},     // 193
	{20, 0b11111111111111101011, '\0'},           // 194
	{19, 0b1111111111111110001, '\0'},            // 195
	{22, 0b1111111111111111100111, '\0'},         // 196
	{23, 0b11111111111111111110010, '\0'},        // 197
	{22, 0b1111111111111111101000, '\0'},         // 198
	{25, 0b1111111111111111111101100, '\0'},      // 199
	{26, 0b11111111111111111111100010, '\0'},     // 200
	{26, 0b11111111111111111111100011, '\0'},     // 201
	{26, 0b11111111111111111111100100, '\0'},     // 202
	{27, 0b111111111111111111111011110, '\0'},    // 203
	{27, 0b111111111111111111111011111, '\0'},    // 204
	{26, 0b11111111111111111111100101, '\0'},     // 205
	{24, 0b111111111111111111110001, '\0'},       // 206
	{25, 0b1111111111111111111101101, '\0'},      // 207
	{19, 0b1111111111111110010, '\0'},            // 208
	{21, 0b111111111111111100011, '\0'},          // 209
	{26, 0b11111111111111111111100110, '\0'},     // 210
	{27, 0b111111111111111111111100000, '\0'},    // 211
	{27, 0b111111111111111111111100001, '\0'},    // 212
	{26, 0b11111111111111111111100111, '\0'},     // 213
	{27, 0b111111111111111111111100010, '\0'},    // 214
	{24, 0b111111111111111111110010, '\0'},       // 215
	{21, 0b111111111111111100100, '\0'},          // 216
	{21, 0b111111111111111100101, '\0'},          // 217
	{26, 0b11111111111111111111101000, '\0'},     // 218
	{26, 0b11111111111111111111101001, '\0'},     // 219
	{28, 0b1111111111111111111111111101, '\0'},   // 220
	{27, 0b111111111111111111111100011, '\0'},    // 221
	{27, 0b111111111111111111111100100, '\0'},    // 222
	{27, 0b111111111111111111111100101, '\0'},    // 223
	{20, 0b11111111111111101100, '\0'},           // 224
	{24, 0b111111111111111111110011, '\0'},       // 225
	{20, 0b11111111111111101101, '\0'},           // 226
	{21, 0b111111111111111100110, '\0'},          // 227
	{22, 0b1111111111111111101001, '\0'},         // 228
	{21, 0b111111111111111100111, '\0'},          // 229
	{21, 0b111111111111111101000, '\0'},          // 230
	{23, 0b11111111111111111110011, '\0'},        // 231
	{22, 0b1111111111111111101010, '\0'},         // 232
	{22, 0b1111111111111111101011, '\0'},         // 233
	{25, 0b1111111111111111111101110, '\0'},      // 234
	{25, 0b1111111111111111111101111, '\0'},      // 235
	{24, 0b111111111111111111110100, '\0'},       // 236
	{24, 0b111111111111111111110101, '\0'},       // 237
	{26, 0b11111111111111111111101010, '\0'},     // 238
	{23, 0b11111111111111111110100, '\0'},        // 239
	{26, 0b11111111111111111111101011, '\0'},     // 240
	{27, 0b111111111111111111111100110, '\0'},    // 241
	{26, 0b11111111111111111111101100, '\0'},     // 242
	{26, 0b11111111111111111111101101, '\0'},     // 243
	{27, 0b111111111111111111111100111, '\0'},    // 244
	{27, 0b111111111111111111111101000, '\0'},    // 245
	{27, 0b111111111111111111111101001, '\0'},    // 246
	{27, 0b111111111111111111111101010, '\0'},    // 247
	{27, 0b111111111111111111111101011, '\0'},    // 248
	{28, 0b1111111111111111111111111110, '\0'},   // 249
	{27, 0b111111111111111111111101100, '\0'},    // 250
	{27, 0b111111111111111111111101101, '\0'},    // 251
	{27, 0b111111111111111111111101110, '\0'},    // 252
	{27, 0b111111111111111111111101111, '\0'},    // 253
	{27, 0b111111111111111111111110000, '\0'},    // 254
	{26, 0b11111111111111111111101110, '\0'},     // 255
	{30, 0b111111111111111111111111111111, '\0'}, // 256
	{0, 0, '\0'}
};

} // namespace

void HuffmanCode::decodeHuffman(unsigned char* p, unsigned int length){

	unsigned int bitvalue = 0;    // huffman_code_tableと照合するためのビット値
	unsigned int bitcounter = 0;  // huffman_code_tableと照合するためのビット数
	unsigned int total_length = 0;

	// whileでは1 octet毎に処理を進める。
	printf("\tParse Value:");
	while(1){
		// octetを取得して、ポインタを進める
		unsigned int octet;
		octet = p[0];
		p++;

		// ビット毎に処理を行う(先頭ビットから順にハフマンテーブルとの照合を行う)
		for(unsigned int i = 1; i <= 8; i++){
			// ビット列を左に1ビットずらすために2倍する
			bitvalue = bitvalue << 1;

			// 先頭からiビット目(8-iを左シフト)の文字列を取得して加算する。bitカウンターもインクリメント
			bitvalue += (octet >> (8-i)) & 1;
			bitcounter++;
//			printf(BYTE_TO_BINARY_PATTERN ", Hex: %02X\n", BYTE_TO_BINARY(bitvalue), bitvalue);

			// スタティックテーブルとの照合処理を行う
			// 照合処理を行うためにhuffman_code_tableに定義された数でループ
			unsigned int tablesize = sizeof(huffman_code_table)/sizeof(huffman_code_table[0]);
			for(unsigned int tbl_index = 0; tbl_index < tablesize; tbl_index++){

				// huffman_code_tableの最大長(EOF)にマッチしたらスキップ
				if( tbl_index == tablesize -1 ){
					// do nothing
				} else if( ( bitcounter == huffman_code_table[tbl_index].len ) && (bitvalue == huffman_code_table[tbl_index].bits) ){
//					printf("%02x", bitvalue);
//					printf("tbl_index=%d, len=%d, string=%c \n", tbl_index, huffman_code_table[tbl_index].len, huffman_code_table[tbl_index].string);
					printf("%c", huffman_code_table[tbl_index].string);

					// 照合されたら一旦カウンターや値をリセット
					bitvalue = 0;
					bitcounter = 0;
					total_length++;
				}
			}
		}

		// 残り処理バイト数が存在しなければ処理を終了する
		length = length -1;
		if(length == 0){
			printf("\n");
			break;
		}
	}

	printf("total length with decoded huffman: %d\n", total_length);
}

