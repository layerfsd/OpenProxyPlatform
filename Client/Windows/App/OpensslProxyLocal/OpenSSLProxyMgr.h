#pragma once

/*�����Ĺ�����*/
typedef struct tagMgrContext
{
	PWORKER_CTX_S				pstWorkerCtx;				/*�����̹߳���������*/
	PDISPATCHPACK_CTX_S		pstClientDispatchCtx;	/*�ͻ����½��ɷ��߳�*/
	ULONG								ulProcessID;					/*��ǰ����ID*/
	USHORT								usListenPort;				/*��ǰ�˿�*/
}MGR_CTX_S, *PMGR_CTX_S;


INT32	OpenSSLProxy_MgrInit();

VOID	OpenSSLProxy_MgrUnInit();

VOID	OpensslProxy_utils_GenUniqueID(CHAR *pcGuID);