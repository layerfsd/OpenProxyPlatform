#include <Winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <process.h>
#include "../common/CLog.h"
#include "../common/CommDef.h"
#include "../common/CommBizDefine.h"
#include "../common/Sem.h"
#include "../common/Queue.h"
#include "OpensslProxyWorker.h"
#include "OpensslProxyPacketDispatch.h"
#include "OpenSSLProxyMgr.h"


SOCKET OpensslProxy_SocketWithTcpPort(USHORT usPort)
{
	SOCKET					sSeverSock = INVALID_SOCKET;
	SOCKADDR_IN		stSockaddr = { 0 };
	INT32						iSocklen	= sizeof(SOCKADDR_IN);
	INT32						iError	    = 0;
	BOOL						bVal			= TRUE;
	int							iOptval		= 1;
	int							iRead		= SOCKET_ERROR;

	sSeverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sSeverSock)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "tcp socket create error=%d", GetLastError());
		return INVALID_SOCKET;
	}

	//stSockaddr.sin_addr.S_un.S_addr = inet_addr(MGR_LOCALADDRA);
    //stSockaddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    //stSockaddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    inet_pton(AF_INET, MGR_LOCALADDRA, &stSockaddr.sin_addr);
	stSockaddr.sin_family = AF_INET;
	stSockaddr.sin_port = htons(usPort);

    /*端口独占和端口复用是不能够一起使用的，提示无效参数*/
#if 0
    iRead = setsockopt(sSeverSock,
        SOL_SOCKET,
        SO_EXCLUSIVEADDRUSE,
        (char*)&iOptval,
        sizeof(iOptval));
    if (iRead == SOCKET_ERROR)
    {
        CLOG_writelog_level("TCPSEV", CLOG_LEVEL_ERROR, "tcp socket set SO_EXCLUSIVEADDRUSE error=%d, usPort=%d", GetLastError(), usPort);
        return INVALID_SOCKET;
    }
#endif

    if (SOCKET_ERROR == setsockopt(sSeverSock, SOL_SOCKET, SO_REUSEADDR, (char *)&iOptval, sizeof(iOptval)))
    {
        CLOG_writelog_level("TCPSEV", CLOG_LEVEL_ERROR, "tcp socket set SO_REUSEADDR error=%d, usPort=%d", GetLastError(), usPort);
        return INVALID_SOCKET;
    }

    iError = bind(sSeverSock, (struct sockaddr *)&stSockaddr, iSocklen);
	if (0 != iError)
	{
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "tcp socket bind error=%d, usPort=%d", GetLastError(), usPort);
        closesocket(sSeverSock);
        return INVALID_SOCKET;
	}

	if (0 != listen(sSeverSock, MGR_LISTENUMS))
	{
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "tcp socket listen error=%d,  usPort=%d", GetLastError(), usPort);
        closesocket(sSeverSock);
		return INVALID_SOCKET;
	}

	return sSeverSock;
}

unsigned int __stdcall OpensslProxy_LocalAccept(PVOID pvArg)
{
	DWORD		dwThreadID		= GetCurrentThreadId();
	SOCKET		sSockfd			= INVALID_SOCKET;
	INT32			isocklen			= sizeof(SOCKADDR);
	UINT32		uiPthreadID		= 0;
	USHORT		usPort				= MGR_LISTENPORT;
    USHORT      usClientPort    = 0;
    CHAR           acAddr[MGR_IPV4LEN] = {0};
	DISPATCHPACK_CTX_S *pstPackDispatch = (DISPATCHPACK_CTX_S *)pvArg;

	if (NULL == pvArg)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "thread param error!");
        SetEvent(pstPackDispatch->hCompleteEvent);
        return -1;
	}

    sSockfd = OpensslProxy_SocketWithTcpPort(usPort);
    if (INVALID_SOCKET == sSockfd )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "create tcp server socket error!");
        SetEvent(pstPackDispatch->hCompleteEvent);
        return -1;
    }
    
    pstPackDispatch->stServerInfo.sSockfd = sSockfd;
    pstPackDispatch->stServerInfo.usPort   = usPort;

	SetEvent(pstPackDispatch->hCompleteEvent);
	
    while (true)
    {
        pstPackDispatch->pstClientInfo = (PCLIENT_INFO_S)malloc(sizeof(CLIENT_INFO_S));
        if (NULL == pstPackDispatch)
        {
            CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "malloc new client info error=%08x!", GetLastError() );
            break;
        }

        pstPackDispatch->pstClientInfo->sLocalFD = accept(sSockfd, (struct sockaddr *)&pstPackDispatch->pstClientInfo->stLocalInfo, &isocklen);
        if (INVALID_SOCKET != pstPackDispatch->pstClientInfo->sLocalFD)
        {
            inet_ntop(AF_INET, &pstPackDispatch->pstClientInfo->stLocalInfo.sin_addr, acAddr, MGR_IPV4LEN);
            usClientPort = ntohs(pstPackDispatch->pstClientInfo->stLocalInfo.sin_port);
            CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "Accept a new Local client info=%s:%d!", acAddr, usClientPort);
            

        }
        else
        {
            printf("accept error=%08x!\n", GetLastError());
            CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "accept error=%08x!", GetLastError());
            free(pstPackDispatch->pstClientInfo);
            pstPackDispatch->pstClientInfo = NULL;
            break;
        }
	}

    CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "local accept thread has end!");

	return 0;
}

DISPATCHPACK_CTX_S *OpensslProxy_DispatchPackCtxCreate()
{
	DISPATCHPACK_CTX_S *pstPackDispatch = NULL;
	DWORD							dwStatckSize = MGR_STACKSIZE;

	pstPackDispatch = (DISPATCHPACK_CTX_S *)malloc(sizeof(DISPATCHPACK_CTX_S));
	if (NULL == pstPackDispatch )
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Malloc dispatch ctx error!");
		return NULL;
	}

	RtlZeroMemory(pstPackDispatch, sizeof(DISPATCHPACK_CTX_S));
    pstPackDispatch->iErrorCode = MGR_ERRCODE_SUCCESS;

	pstPackDispatch->hCompleteEvent =CreateEvent(NULL, FALSE, FALSE, NULL);
	if (NULL == pstPackDispatch->hCompleteEvent )
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Dispatch ctx create complete event error!");
		free(pstPackDispatch);
		pstPackDispatch = NULL;
		return NULL;
	}

	/*直接在当前线程先创建Accept的本地服务端*/
    pstPackDispatch->hThreadHandle = _beginthreadex(NULL, dwStatckSize, OpensslProxy_LocalAccept, pstPackDispatch, 0, NULL);

    WaitForSingleObject(pstPackDispatch->hCompleteEvent, INFINITE);

    /*表示线程初始化过程中存在问题，直接退出*/
    if (pstPackDispatch->iErrorCode != MGR_ERRCODE_SUCCESS )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Dispatch pthread init errorCode=%d", pstPackDispatch->iErrorCode);
        CloseHandle(pstPackDispatch->hCompleteEvent);
        free(pstPackDispatch);
        pstPackDispatch = NULL;
        return NULL;
    }

    CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "***INIT***: Local Server Start successful! Socket=%d, port=%d", 
        pstPackDispatch->stServerInfo.sSockfd, pstPackDispatch->stServerInfo.usPort);

	return pstPackDispatch;
}


VOID OpensslProxy_DispatchPackCtxRelease(PDISPATCHPACK_CTX_S pstDispatchCtx)
{
	if (NULL == pstDispatchCtx )
	{
		if (NULL != pstDispatchCtx->hCompleteEvent )
		{
			CloseHandle(pstDispatchCtx->hCompleteEvent);
		}
		free(pstDispatchCtx);
	}
}















