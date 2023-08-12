#include "agentServer.h"
#include "net_header.h"
#include "packet.h"
#include "platform_log.h"
#include "http_defines.h"
#include "platform_log.h"
#include "platform_common.h"
#include "agent_server_util.h"
#include "agentSession.h"
#include "targetSession.h"
#include <string_util.h>
#include <url.h>
#include <json.hpp>
#include <platform_file_system.h>
#include <platform_file.h>
#include <net_session.h>

AgentServer::AgentServer()
{
	
}

AgentServer::~AgentServer()
{

}

void AgentServer::OnPreInit()
{
	_load_config();

	_http_agent_session = new NetSession(this, false);
}


void AgentServer::OnAccept(NetHandle h, const session_info_t& data, void* pNetThreadData)
{
	NOTICE_LOG("%s:%d connected, server:%s:%d, handle:%llu\n", 
		data.peer_ip, data.peer_port, data.local_ip, data.local_port, h);


	AgentSession* session = nullptr;

	session = new AgentSession(h, this);

	_session_map[h] = session;

	
}

void AgentServer::OnConnected(NetHandle h, const session_info_t& data, void* pNetThreadData)
{
	NOTICE_LOG("%s:%d dconnected, server:%s:%d, handle:%llu\n",
		data.peer_ip, data.peer_port, data.local_ip, data.local_port, h);
	auto itor = _target_map.find(h);
	if (itor != _target_map.end())
	{
		itor->second->OnConnected(h, data);
	}
}

void AgentServer::OnClose(NetHandle h, const session_info_t& data, void* pNetThreadData)
{
	if (data.is_client)
	{
		NOTICE_LOG("[target_handle:%llu]%s:%d disconnected, server:%s:%d\n",
			h, data.peer_ip, data.peer_port, data.local_ip, data.local_port);
		auto itor = _target_map.find(h);

		if (itor != _target_map.end())
		{
			itor->second->OnClose(h, data);
		}
	}
	else
	{
		NOTICE_LOG("[usr_handle:%llu]%s:%d disconnected, server:%s:%d\n",
			h, data.peer_ip, data.peer_port, data.local_ip, data.local_port);
		auto itor = _session_map.find(h);

		if (itor != _session_map.end())
		{
			itor->second->OnClose(data);
			delete itor->second;
			_session_map.erase(itor);
		}
		else
		{
			WARNING_LOG("[usr_handle:%llu]fail to find session", h);
		}
	}
	
}

int AgentServer::process_message(NetHandle handle, const char* msg, uint32_t msg_size, void* pNetThreadData)
{
	auto itor = _target_map.find(handle);

	if (itor != _target_map.end())
	{
		itor->second->OnRecvData(msg, msg_size);
	}

	return 0;
}

int AgentServer::process_custom_message(uint64_t param, const char* msg, uint32_t msg_size, void* pNetThreadData)
{
	if (param == CUSTOM_MESSAGE_DNS_RESULT)
	{
		AgentDnsUserData* usrdata = *(AgentDnsUserData**)msg;
		_dns_result(usrdata);
		delete usrdata;
	}
	return 0;
}

void AgentServer::OnHttpAgentData(NetHandle handle, const char* data, uint32_t size, void* pNetThreadData)
{
	NOTICE_LOG("[usr_handle:%llu, size:%d]recv user data", handle, size);
	auto itor = _session_map.find(handle);

	if (itor != _session_map.end())
	{
		itor->second->ProcessDataToTarget(data, size);
	}
}

void AgentServer::OnHttpHeader(NetHandle handle, const std::string& location, struct HttpContent* content, void* pNetThreadData)
{
	NOTICE_LOG("[usr_handle:%llu]http loc:%s, proto:%s\n", handle, location.c_str(), content->proto.c_str());
	if (location[0] == '/')
	{
		_private_api(handle, content);
		return;
	}

	

	auto itor = _session_map.find(handle);

	if (itor != _session_map.end())
	{
		itor->second->ProcessHttpHeader(location, content);
	}
}


platform_timer_t AgentServer::CreateTimer(NetHandle sessionHandle, int32_t duration, void* param, bool loop)
{
	AgentTimer* timer = new AgentTimer;
	timer->_param = param;
	timer->_session_handle = sessionHandle;
	timer->_server = this;
	timer->_timer_handle = create_timer(duration, timer, loop);
	timer->_loop = loop;
	_session_timer_map[timer->_timer_handle] = timer;

	return timer->_timer_handle;
}

bool AgentServer::ReleaseTimer(platform_timer_t timerHandle)
{
	bool b = delete_timer(timerHandle);
	auto itor = _session_timer_map.find(timerHandle);

	if (itor != _session_timer_map.end())
	{
		delete itor->second;
		_session_timer_map.erase(itor);
	}

	return b;
}


void AgentServer::CloseTarget(NetHandle h)
{
	auto itor = _target_map.find(h);

	if (itor != _target_map.end())
	{
		delete itor->second;
		_target_map.erase(itor);
	}

	NetFactory::GetInstance()->CloseNetHandle(h);
}

static void agent_dns_callback(dy_dns_t* dummy)
{
	AgentDnsUserData* dnsResult = (AgentDnsUserData*)dummy->_user_data;
	dnsResult->_ip_list = dummy->_ip_list;
	dnsResult->_dns_err = dummy->_dns_error;
	dnsResult->_agent->post_custom_message(0, CUSTOM_MESSAGE_DNS_RESULT, (const uint8_t*)&dnsResult, sizeof(AgentDnsUserData*), nullptr);
}

void AgentServer::_connect_target(const std::string& target_server, uint32_t target_port, AgentSession* session)
{
	if (util::is_ipv4(target_server))
	{
		SessionData data;
		data.m_PeerIP = target_server;
		data.m_PeerPort = target_port;
		TargetSession* target = new TargetSession(session);
		data.m_param = (void*)target;
		NetHandle targetHandle = NetFactory::GetInstance()->CreateTcpConnection((INetSession*)_http_agent_session, data);

		NOTICE_LOG("[usr_handle:%llu, target_handle:%llu, target:%s:%d]connect to target server",
			session->getNetHandle(), targetHandle, data.m_PeerIP.c_str(), data.m_PeerPort);
		_target_map[targetHandle] = target;
	}
	else
	{
		AgentDnsUserData* usrdata = new AgentDnsUserData;
		usrdata->_agent = this;
		usrdata->_handle = session->getNetHandle();
		usrdata->_domain = target_server;
		usrdata->_port = target_port;
		dns_resolve(target_server, agent_dns_callback, usrdata);
	}
}

void AgentServer::OnTimer(platform_timer_t timerHandle, void* param)
{
	AgentTimer* timer = (AgentTimer*)param;

	auto session = _session_map.find(timer->_session_handle);

	if (session != _session_map.end())
	{
		session->second->ProcessTimeout(timerHandle, timer->_param);
	}

	if (!timer->_loop)
	{
		ReleaseTimer(timerHandle);
	}
	
}

void AgentServer::_load_config()
{
	std::string name = CPlatformFileSystem::GetInstance()->GetProcessDirectory() + "/agentserver.json";

	std::string content;
	if (!get_file_content(name.c_str(), content))
	{
		NOTICE_LOG("load config file failed, %s", name.c_str());
	}
	else
	{
		nlohmann::json j3 = nlohmann::json::parse(content, nullptr, false);

		if (j3.is_discarded())
		{
			WARNING_LOG("json::parse error!%s", content.c_str());
			return;
		}

		if (j3["http_port"].is_number_integer())
		{
			_server_config._http_port = j3["http_port"].get<int>();
		}

		if (j3["agent_port"].is_number_integer())
		{
			_server_config._agent_port = j3["agent_port"].get<int>();
		}

		if (j3["io_thread_count"].is_number_integer())
		{
			_server_config._io_thread_count = j3["io_thread_count"].get<int>();
		}

		if (j3["work_thread_count"].is_number_integer())
		{
			_server_config._worker_thread_count = j3["work_thread_count"].get<int>();
		}

		if (j3["report_ip"].is_string())
		{
			_server_config._report_ip = j3["report_ip"].get<std::string>();
		}

		if (j3["upload_ip"].is_string())
		{
			_server_config._upload_ip = j3["upload_ip"].get<std::string>();
		}

		if (j3["upload_port"].is_number_integer())
		{
			_server_config._upload_port = j3["upload_port"].get<int>();
		}

		if (j3["upload_duration"].is_number_integer())
		{
			_server_config._upload_duration = j3["upload_duration"].get<int>();
		}

		if (j3["download_url"].is_string())
		{
			_server_config._download_url = j3["download_url"].get<std::string>();
		}
	}
	
	NOTICE_LOG("load config sucessfully.[http_port:%d][agent_port:%d][io_count:%d][worker_count:%d][report_ip:%s]",
		_server_config._http_port, _server_config._agent_port, _server_config._io_thread_count, _server_config._worker_thread_count, _server_config._report_ip.c_str());

	NOTICE_LOG("test spped param.[upload_ip:%s:%d][upload_duration:%d][download_url:%s]",
		_server_config._upload_ip.c_str(), _server_config._upload_port, _server_config._upload_duration, _server_config._download_url.c_str());
}

void AgentServer::_private_api(NetHandle handle, struct HttpContent* content)
{
	std::string location = content->location;
	auto pos = content->location.find_first_of('?');

	std::map<string_view, string_view> kv;
	std::string params;
	if (pos != std::string::npos)
	{
		location = location.substr(0, pos);

		params = content->location.substr(pos + 1, content->location.size());
		util::parse_url_args(params, &kv);
	}

	
	send_http_json_response(handle, -1, "location error");
}

void AgentServer::_dns_result(AgentDnsUserData* usrdata)
{
	if (usrdata->_ip_list.empty())
	{
		WARNING_LOG("dns failed, domain:%s", usrdata->_domain.c_str());

		auto itor = _session_map.find(usrdata->_handle);

		if (itor != _session_map.end())
		{
			itor->second->ProcessDnsFailed();
		}
		
	}
	else
	{

		auto itor = _session_map.find(usrdata->_handle);

		if (itor == _session_map.end())
		{
			return;
		}
		SessionData data;

		auto idx = rand() % usrdata->_ip_list.size();
		data.m_PeerIP = usrdata->_ip_list[idx];
		data.m_PeerPort = usrdata->_port;

		TargetSession* target = new TargetSession(itor->second);
		data.m_param = (void*)target;
		NetHandle targetHandle = NetFactory::GetInstance()->CreateTcpConnection((INetSession*)_http_agent_session, data);

		_target_map[targetHandle] = target;
		NOTICE_LOG("[usr_handle:%llu, target_handle:%llu, target:%s:%d, domain:%s]create connection to target server",
			itor->second->getNetHandle(), targetHandle, data.m_PeerIP.c_str(), data.m_PeerPort, usrdata->_domain.c_str());
	}
}