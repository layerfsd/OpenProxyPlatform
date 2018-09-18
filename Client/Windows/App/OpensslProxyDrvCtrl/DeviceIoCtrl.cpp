#include <string.h>
#include <stdio.h>
#include "../common/CLog.h"
#include "../common/CrashDump.h"
#include "DrvCtrlApi.h"
#include "DeviceIoCtrl.h"
#include "DevControlDefine.h"


#define     DRV_BUFSIZE       4096

DeviceIoCtrl::DeviceIoCtrl()
{
	m_hDev = INVALID_HANDLE_VALUE;
}

DeviceIoCtrl::~DeviceIoCtrl()
{

}

BOOLEAN DeviceIoCtrl::OpenDev()
{
	if ( m_hDev == INVALID_HANDLE_VALUE )
	{
		m_hDev = ::CreateFile(
				L"\\\\.\\OpenSSLProxyDriver", 
				GENERIC_READ | GENERIC_WRITE, 
				0, 
				NULL, 
				OPEN_EXISTING, 
				NULL, 
				NULL );
		if ( m_hDev == INVALID_HANDLE_VALUE )
		{
			CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Create OpenSSLProxy Driver error=%08x!", GetLastError());
			return FALSE;
		}
		return TRUE;
	}

	return FALSE;
}

void DeviceIoCtrl::CloseDev()
{
	if (m_hDev != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hDev);
		m_hDev = INVALID_HANDLE_VALUE;
	}
}

BOOLEAN DeviceIoCtrl::RuleMatchEnable()
{
	DWORD			dwRet = 0;

	if (m_hDev == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if ( 0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_MATCHENABLE, NULL, 0, NULL, NULL, &dwRet, NULL))
	{
		CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  rule-match  enable error=%08x!", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOLEAN DeviceIoCtrl::RuleMatchDisable()
{
	DWORD			dwRet = 0;

	if (m_hDev == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	if ( 0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_MATCHDISABLE, NULL, 0, NULL, NULL, &dwRet, NULL) )
	{
		CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  rule-match disable error=%08x!", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOLEAN	DeviceIoCtrl::SetLocalProxyInfo(UINT32 uiLocalPID, UINT32 uiLocalPort)
{
	DWORD											dwRet = 0;
	DWORD											dwSize = 0;
	DEVICE_IOCTL_SETPROXYINFO		stProxyInfo = {0};

	if (m_hDev == INVALID_HANDLE_VALUE
		|| uiLocalPort > 65500 )
	{
		return FALSE;
	}

	stProxyInfo.uiPID = uiLocalPID;
	stProxyInfo.uiTcpPort = uiLocalPort;
	dwSize = sizeof(stProxyInfo);

	if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_SETLOCALPROXY, &stProxyInfo, dwSize, NULL, NULL, &dwRet, NULL))
	{
		CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  set local Proxy Info error=%08x!", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOLEAN	DeviceIoCtrl::SetRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort)
{
    DWORD											dwRet       = 0;
    DWORD											dwSize      = 0;
    DEVICE_IOCTL_RULEINFO		        stIPAddr    = { 0 };

    if ( uiIPAddr == 0
        && uiIPPort == 0 )
    {
        return FALSE;
    }

    stIPAddr.uiRuleIPAddr = uiIPAddr;
    stIPAddr.uiRulePort     = uiIPPort;
    dwSize = sizeof(stIPAddr);

    if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_SETRULEIPPORT, &stIPAddr, dwSize, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  set ip addr and port  error=%08x!", GetLastError());
        return FALSE;
    }

    return TRUE;
}


BOOLEAN	DeviceIoCtrl::DelRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort)
{
    DWORD											dwRet = 0;
    DWORD											dwSize = 0;
    DEVICE_IOCTL_RULEINFO		        stIPAddr = { 0 };

    if (uiIPAddr == 0
        && uiIPPort == 0)
    {
        return FALSE;
    }

    stIPAddr.uiRuleIPAddr = uiIPAddr;
    stIPAddr.uiRulePort = uiIPPort;
    dwSize = sizeof(stIPAddr);

    if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_DELRULEIPPORT, &stIPAddr, dwSize, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  clear-rule ipaddr and port  error=%08x!", GetLastError());
        return FALSE;
    }

    return TRUE;
}



BOOLEAN	DeviceIoCtrl::ClearRuleIPAddrWithType(UINT32 uiType)
{
    DWORD						 dwRet = 0;
    DWORD                       dwType = 0;
    DWORD                       dwSize = sizeof(DWORD);

    dwType = uiType;

    if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_SETRULETYPECLEAR, &dwType, dwSize, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  clear-rule ipaddr and port with type:[%d] error=%08x!", dwType, GetLastError());
        return FALSE;
    }

    return TRUE;
}


BOOLEAN	DeviceIoCtrl::ClearRuleIPAddr()
{
    DWORD											dwRet = 0;

    if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_SETRULECLEAR, NULL, 0, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  delete ip addr and port  error=%08x!", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOLEAN	DeviceIoCtrl::SetLocalPortRange(UINT32 uiLocalStart, UINT32 uiLocalEnd)
{
    DWORD											dwRet = 0;
    DWORD											dwSize = 0;
    DEVICE_IOCTL_PORTRANGE_S		stRange = { 0 };

    if (uiLocalStart > 65500
        || uiLocalEnd > 65500 )
    {
        return FALSE;
    }

    stRange.uiLocalPortStart = uiLocalStart;
    stRange.uiLocalPortEnd = uiLocalEnd;

    dwSize = sizeof(stRange);

    if (0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_SETPORTRANGE, &stRange, dwSize, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  set port Range Info error=%08x!", GetLastError());
        return FALSE;
    }

    return TRUE;
}

/*安全的进行拷贝*/
UINT32	DeviceIoCtrl::GetLocalPortRange(CHAR *pcBuf, INT32 uiBufLen)
{
    DWORD											dwRet = 0;
    DWORD											dwSize = DRV_BUFSIZE;
    DEVICE_IOCTL_SETPROXYINFO		stProxyInfo = { 0 };
    CHAR                                               acBuf[DRV_BUFSIZE] = {0};

    if ( pcBuf == NULL 
        || uiBufLen < DRV_BUFSIZE )
    {
        return FALSE;
    }

    if ( 0 == DeviceIoControl(m_hDev, DEVICE_IOCTL_GETPORTRANGE, &acBuf, dwSize, NULL, NULL, &dwRet, NULL))
    {
        CLOG_writelog_level("DEVCTL", CLOG_LEVEL_ERROR, "Device  get port range error=%08x!", GetLastError());
        return FALSE;
    }
    else
    {
        if (dwRet == 0 )
        {
            return 0;
        }
        else
        {
            /*直接拷贝出去即可*/
            RtlCopyMemory(pcBuf, acBuf, DRV_BUFSIZE);
        }
    }

    return dwRet;
}
