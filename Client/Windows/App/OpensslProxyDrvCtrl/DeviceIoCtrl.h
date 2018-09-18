#pragma once

class  DeviceIoCtrl
{
	public:
		DeviceIoCtrl();
		 virtual ~DeviceIoCtrl();

		 //¿ØÖÆ½Ó¿Ú
		 BOOLEAN	OpenDev();
		 void				CloseDev();

		 BOOLEAN	RuleMatchEnable();
		 BOOLEAN	RuleMatchDisable();

		 BOOLEAN	SetLocalProxyInfo(UINT32 uiLocalPID, UINT32 uiLocalPort);

         BOOLEAN   SetRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort);
         BOOLEAN   DelRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort);
         BOOLEAN   ClearRuleIPAddr();
         BOOLEAN   ClearRuleIPAddrWithType(UINT32 uiType);

         BOOLEAN   SetLocalPortRange(UINT32 uiLocalStart, UINT32 uiLocalEnd);
         UINT32       GetLocalPortRange(CHAR *pcBuf, INT32 uiBufLen);

	private:
		HANDLE	m_hDev;
		ULONG	m_nErrorCode;
};





