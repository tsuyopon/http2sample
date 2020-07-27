#include "RequestUtil.h"
#include <algorithm>

// URLをパースして、schme, host, pathを返す
int8_t RequestUtil::parseUrl(std::string url, std::string &scheme, std::string &host, std::string &path){

	std::string https_prefix = "https://";
	if (url.size() > https_prefix.size() && std::equal(std::begin(https_prefix), std::end(https_prefix), std::begin(url))) {  // 先頭prefixに一致することの確認
		scheme = "https";  // https以外返さない

		// 先頭から8byte(https://)は除去
		url.erase(0, https_prefix.size());

		// FIXME: urlはポート番号(:443等)は考慮していない
		// スラッシュ(/)で前後を分解して、前はドメイン、後ろはURLとする。スラッシュが存在しない場合はpathに"/"を指定する。
		size_t slash_pos = url.find("/");
		if( slash_pos == std::string::npos) {
			// not found slash
			host = url;  
			path = "/";
		} else {
			// found slash
			host =  url.substr(0, url.find("/"));
			path =  url.substr(url.find("/"));
		}
	} else {
		printf("URL Parse Error. Maybe \"https://\" is not include.\n");
		return -1;
	}
	return 0;
}

// 大文字を小文字に変換する
char RequestUtil::asciitolower(char in) {
	if (in <= 'Z' && in >= 'A')
		return in - ('Z' - 'z');
	return in;
}

// ヘッダで「Name: Value」形式を分解して、header_name、header_valueに値を格納する
int8_t RequestUtil::parseHeader(std::string header, std::string &header_name, std::string &header_value){
	size_t colon_pos = header.find(":");
	if( colon_pos == std::string::npos) {
		printf("Header Parser Error. \":\" separate field is not found\n");
		return -1;
	}
	header_name =  header.substr(0, header.find(":"));
	// header field names MUST be converted to lowercase prior to their encoding in HTTP/2.  A request or response containing uppercase header field names MUST be treated as malformed (sec8.1.2)
	std::transform(header_name.begin(), header_name.end(), header_name.begin(), RequestUtil::asciitolower);

	header_value=  header.substr(header.find(":"));
	return 0;
}
