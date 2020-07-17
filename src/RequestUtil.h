#pragma once
#include<string>
#include<iostream>

class RequestUtil {
public:
	static int8_t parseUrl(std::string url, std::string &scheme, std::string &host, std::string &path);
	static char asciitolower(char in);
	static int8_t parseHeader(std::string header, std::string &header_name, std::string &header_value);
};

