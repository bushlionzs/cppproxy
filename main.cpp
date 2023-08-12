#include <iostream>
#include <net_lib.h>
#include <platform_log.h>
#include "agentServer.h"
#include "url.h"
#include <json.hpp>
#include <map>
#include <string>
#include <platform_device.h>
#include <time_util.h>
#include "net_speed.h"
#include "file_upload.h"







static void handle_test(int sig)
{
   
}

int main()
{

#ifndef _WIN32
    signal(SIGPIPE, handle_test);
#endif
    platform_log_init();
    
    netlib_init();
   
    AgentServer server;

    server.init();

    printf("agent server is running!!!\n");
    server.start(true);

}

