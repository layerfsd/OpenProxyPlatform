#pragma once


/*���ؾ����㷨*/
typedef enum
{
	PROXY_BLANCEALGM_LEASTCONN = 0,

	PROXY_BLANCEALGM_NUMS
}PROXY_BLANALGM_E;

typedef struct tagLocalServerInfo
{
    SOCKET           sSockfd;
    USHORT          usPort;
    UINT32            uiPID; 
}LOCAL_SEVINFO_S,*PLOCAL_SEVINFO_S;

/*�����ı��ص�socket��Ϣ*/
typedef struct tagLocalSockInfo
{
	SOCKET			    sLocalFD;					/*���ص�Socket��Ϣ*/
	SOCKADDR_IN	stLocalInfo;				/*���ص�Socket��Ϣ*/
}CLIENT_INFO_S, *PCLIENT_INFO_S;

/*����ת��������: TODO: ������һЩ���˵Ĳ���*/
typedef struct tagDispatchPackContext
{
	HANDLE				    hThreadHandle;		/*�̵߳ȴ����*/
	HANDLE				    hCompleteEvent;		/*����¼�*/
    LOCAL_SEVINFO_S  stServerInfo;            /*�����ȷ��ڱ��߳�*/
	PCLIENT_INFO_S	    pstClientInfo;			/*�µĿͻ���������Ϣ*/
	ULONG				    ulBlanceAlgm;			/*�ַ��ľ����㷨*/
}DISPATCHPACK_CTX_S, *PDISPATCHPACK_CTX_S;


DISPATCHPACK_CTX_S *OpensslProxy_DispatchPackCtxCreate();

VOID OpensslProxy_DispatchPackCtxRelease(PDISPATCHPACK_CTX_S pstDispatchCtx);





