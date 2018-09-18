// OpensslProxyLocal.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <process.h>
#include "../OpensslProxyDrvCtrl/DrvCtrlApi.h"
#include "../common/CLog.h"
#include "../common/CommDef.h"
#include "../common/CommBizDefine.h"
#include "../common/Sem.h"
#include "../common/Queue.h"
#include "OpensslProxyWorker.h"
#include "OpensslProxyPacketDispatch.h"
#include "OpenSSLProxyMgr.h"


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "OpensslProxyDrvCtrl.lib")

int main(int argc, char *argv[])
{
    UINT32          uiIPAddr   = 0;
    UINT32          uiIPPort    = 0;

    if (argc < 2 )
    {
        printf("Usage: OpensslProxyLocal.exe  ipaddr port\n");
        return -1;
    }
    else
    {
        uiIPAddr = atoi(argv[1]);
        uiIPPort = atoi(argv[2]);
    }

	/*1. 需要先初始化驱动库*/
	if ( FALSE == OpenSSLProxy_DrvCtrl_EnvLibInit())
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Driver enviroment error!\n");
		goto Exit;
	}
	else
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "***INIT***: OpenSSLProxy Driver enviroment Init OK!");
	}

	/*2. 初始化管理器*/
	if ( SYS_ERR == OpenSSLProxy_MgrInit() )
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Driver enviroment error!\n");
		goto Exit;
	}
	else
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "***INIT***: Local Proxy Manager Init  OK!");
	}

    if ( SYS_ERR == OpenSSLProxy_DrvCtrl_SetRuleIPAddr(uiIPAddr, uiIPPort) )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Set ip-addr and Port error!\n");
        goto Exit;
    }

    /*启动规则匹配*/
    if ( TRUE == OpenSSLProxy_DrvCtrl_RuleMatchEnable() )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Rule enable error!\n");
        goto Exit;
    }
    else
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "***INIT***: Rule match enable successful!");
    }

	system("pause");
Exit:
    OpenSSLProxy_MgrUnInit();
	OpenSSLProxy_DrvCtrl_EnvLibUnInit();
	CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "***STOP***: The End!");
    return 0;
}

