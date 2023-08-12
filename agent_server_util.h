#pragma once


#include <string>
#include <net_handle.h>

void send_http_response(
	NetHandle handle,
	int32_t code, 
	const char* codemsg, 
	const std::string& content);

void send_http_json_response(
	NetHandle handle,
	int32_t code,
	const char* codemsg
	);