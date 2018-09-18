#include <string.h>
#include <stdio.h>
#include "../common/CLog.h"
#include "../common/CrashDump.h"
#include "DrvCtrlApi.h"
#include "DeviceIoCtrl.h"

DeviceIoCtrl *g_pstDevIoCtrl = NULL;

BOOLEAN	OpenSSLProxy_DrvCtrl_EnvLibInit()
{
	/*Lib库不用定义*/
	(VOID)CLOG_evn_init(CLOG_TYPE_DEVCTRL);
	CrashDumpInitialize();

	if ( NULL == g_pstDevIoCtrl )
	{
		g_pstDevIoCtrl = new DeviceIoCtrl;
		if (NULL == g_pstDevIoCtrl )
		{
			CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Create DeviceIoCtrl Class Object error!");
			return FALSE;
		}
		
		if( FALSE == g_pstDevIoCtrl->OpenDev() )
		{
			CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Open Device Handle error!");
			return FALSE;
		}
        else
        {
            if ( FALSE == g_pstDevIoCtrl ->ClearRuleIPAddr() )
            {
                CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Clear Rule IP-Addr error!");
                return FALSE;
            }
        }
		return TRUE;
	}

	return FALSE;
}

VOID OpenSSLProxy_DrvCtrl_EnvLibUnInit()
{
	if (NULL != g_pstDevIoCtrl)
	{
        g_pstDevIoCtrl->RuleMatchDisable();
		g_pstDevIoCtrl->CloseDev();

		delete g_pstDevIoCtrl;
		g_pstDevIoCtrl = NULL;
	}
}



BOOLEAN OpenSSLProxy_DrvCtrl_RuleMatchEnable()
{
	if (NULL != g_pstDevIoCtrl)
	{
		return g_pstDevIoCtrl->RuleMatchEnable();
	}

	return FALSE;
}

BOOLEAN OpenSSLProxy_DrvCtrl_RuleMatchDisable()
{
	if (NULL != g_pstDevIoCtrl)
	{
		return g_pstDevIoCtrl->RuleMatchDisable();
	}

	return FALSE;
}

BOOLEAN	OpenSSLProxy_DrvCtrl_SetLocalProxyInfo(UINT32 uiPID, UINT32 uiTcpPort)
{
	if (NULL != g_pstDevIoCtrl)
	{
		return g_pstDevIoCtrl->SetLocalProxyInfo(uiPID, uiTcpPort);
	}
	return FALSE;
}

BOOLEAN   OpenSSLProxy_DrvCtrl_SetRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort)
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->SetRuleIPAddr(uiIPAddr, uiIPPort);
    }
    return FALSE;
}

BOOLEAN   OpenSSLProxy_DrvCtrl_DelRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort)
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->DelRuleIPAddr(uiIPAddr, uiIPPort);
    }
    return FALSE;
}
BOOLEAN   OpenSSLProxy_DrvCtrl_ClearRuleIPAddr()
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->ClearRuleIPAddr();
    }
    return FALSE;
}
BOOLEAN   OpenSSLProxy_DrvCtrl_ClearRuleIPAddrWithType(UINT32 uiType)
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->ClearRuleIPAddrWithType(uiType);
    }
    return FALSE;
}

BOOLEAN  OpenSSLProxy_DrvCtrl_SetLocalPortRange(UINT32 uiLocalStart, UINT32 uiLocalEnd)
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->SetLocalPortRange(uiLocalStart, uiLocalEnd);
    }
    return FALSE;
}

UINT32      OpenSSLProxy_DrvCtrl_GetLocalPortRange(CHAR *pcBuf, INT32 uiBufLen)
{
    if (NULL != g_pstDevIoCtrl)
    {
        return g_pstDevIoCtrl->GetLocalPortRange(pcBuf, uiBufLen);
    }
    return FALSE;
}






















