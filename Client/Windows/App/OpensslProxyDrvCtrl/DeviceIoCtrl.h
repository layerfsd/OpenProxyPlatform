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

	private:
		HANDLE	m_hDev;
		ULONG	m_nErrorCode;
};





