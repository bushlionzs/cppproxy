#pragma once
#include <stdint.h>
#include <string>
#include <net_handle.h>
#include <server_def.h>
class AgentSession;
class TargetSession
{
public:
	TargetSession(AgentSession* source);

	void OnRecvData(const char* data, uint32_t size);

	void OnConnected(NetHandle h, const session_info_t& data);
	void OnClose(NetHandle h, const session_info_t& data);
private:
	AgentSession* _source;
};