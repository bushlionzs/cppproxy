#include "targetSession.h"
#include "agentSession.h"

TargetSession::TargetSession(AgentSession* source)
{
	_source = source;
}

void TargetSession::OnRecvData(const char* data, uint32_t size)
{
	_source->ProcessAgentDataToUser(data, size);
}

void TargetSession::OnConnected(NetHandle h, const session_info_t& data)
{
	_source->ProcessTargetConnected(h);
}

void TargetSession::OnClose(NetHandle h, const session_info_t& data)
{
	_source->ProcessTargetClose();
}