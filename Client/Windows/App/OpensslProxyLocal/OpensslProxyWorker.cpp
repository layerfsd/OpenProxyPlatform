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
#include "../common/CommIoBuf.h"
#include "OpensslProxyWorker.h"
#include "OpensslProxyPacketDispatch.h"
#include "OpenSSLProxyMgr.h"

INT32       OpensslProxy_SockEventDel(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex);


unsigned int __stdcall OpensslProxy_NetworkEventsWorker(void *pvArgv)
{


    return 0;
}

INT32 OpensslProxy_SockEventCtrl(SOCK_MGR_S *pstSockMgr, UINT32 uiIndex, UINT32 uiCtrlCode)
{
    if ( NULL == pstSockMgr)
    {
        return SYS_ERR;
    }

    switch (uiCtrlCode)
    {
        case SOCKCTRL_SHUTDOWN:
                (VOID)OpensslProxy_SockEventDel(pstSockMgr, uiIndex);
            break;
        case SOCKCTRL_CLOSE_RECV:
            break;
        case SOCKCTRL_OPEN_RECV:
            break;
        case SOCKCTRL_CLOSE_SEND:
            break;
        case SOCKCTRL_OPEN_SEND:
            break;
        case SOCKCTRL_UNKNOW:
        default:
            break;
    }

    return SYS_OK;
}

VOID   OpensslProxy_PerSockInfoReset(PERSOCKINFO_S *pstPerSockInfo)
{
    if ( NULL == pstPerSockInfo )
    {
        return;
    }

    InitializeListHead(&pstPerSockInfo->stNode);
    InitializeListHead(&pstPerSockInfo->stIoBufList);
    pstPerSockInfo->eSockType = SOCKTYPE_UNKNOW;
    pstPerSockInfo->sSockfd = INVALID_SOCKET;
    pstPerSockInfo->hEvtHandle = NULL;
    pstPerSockInfo->lEvtsIndex = -1; 
    pstPerSockInfo->lPeerEvtsIndex = -1;
    pstPerSockInfo->pfSockCtrlCb = OpensslProxy_SockEventCtrl;
}

VOID   OpensslProxy_NetworkEventReset(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex)
{
    if (uiEvtIndex >= WSAEVT_NUMS )
    {
        return;
    }
    pstSockMgr->stNetEvent.arrWSAEvts[uiEvtIndex] = NULL;
    pstSockMgr->stNetEvent.arrSocketEvts[uiEvtIndex] = INVALID_SOCKET;
}

/*获取对端的事件索引*/
INT32    OpensslProxy_GetPeerSockEventIndex(PERSOCKINFO_S *pstPerSockInfo)
{
    return pstPerSockInfo->lPeerEvtsIndex;
}

VOID       OpensslProxy_PerSockEventClear(PERSOCKINFO_S *pstPerSockInfo)
{
    /*直接检查释放掉所有的本Socket相关IoBuf资源*/
    COMM_IOBUF_BufListRelease(&pstPerSockInfo->stIoBufList);

    /*先关闭本socket的所有资源*/
    shutdown(pstPerSockInfo->sSockfd, SD_BOTH);
    closesocket(pstPerSockInfo->sSockfd);
}

INT32       OpensslProxy_UpdateSockEventPeerIndex(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex, UINT32 uiPeerIndex)
{
    if ( NULL == pstSockMgr
        || uiEvtIndex >= WSAEVT_NUMS )
    {
        return SYS_ERR;
    }

    if( INVALID_SOCKET != pstSockMgr->stArrySockInfo[uiEvtIndex].sSockfd )
            pstSockMgr->stArrySockInfo[uiEvtIndex].lPeerEvtsIndex = uiPeerIndex;

    return SYS_OK;
}

INT32       OpensslProxy_SockEventAdd(SOCK_MGR_S *pstSockMgr,SOCKET sSocketFd, UINT32 uiSockType)
{
    if ( NULL == pstSockMgr 
        || INVALID_SOCKET == sSocketFd 
        || pstSockMgr->ulSockNums >= WSAEVT_NUMS-2 )
    {
        return SYS_ERR;
    }

    /*开始进行遍历插入动作*/
    for (int iIndex = 0; iIndex < WSAEVT_NUMS; iIndex++)
    {
        if ( INVALID_SOCKET == pstSockMgr->stArrySockInfo[iIndex].sSockfd )
        {
            /*确保没有乱入残留的数据*/
            InitializeListHead(&pstSockMgr->stArrySockInfo[iIndex].stIoBufList);
            pstSockMgr->stArrySockInfo[iIndex].eSockType = (SOCKTYPE_E)uiSockType;
            pstSockMgr->stArrySockInfo[iIndex].lEvtsIndex = iIndex;
            pstSockMgr->stArrySockInfo[iIndex].sSockfd = sSocketFd;
            pstSockMgr->stArrySockInfo[iIndex].hEvtHandle = WSACreateEvent();

            /*添加到对应的网络事件*/
            pstSockMgr->stNetEvent.arrSocketEvts[iIndex] = sSocketFd;
            pstSockMgr->stNetEvent.arrWSAEvts[iIndex] = pstSockMgr->stArrySockInfo[iIndex].hEvtHandle;
            WSAEventSelect(sSocketFd, pstSockMgr->stNetEvent.arrWSAEvts[iIndex], FD_READ | FD_CLOSE);

            InterlockedIncrement(&pstSockMgr->ulSockNums);
            return SYS_OK;
        }
    }

    return SYS_ERR;
}

/*删除本网络事件，注意： 确保在删除之前，将对端也删除*/
INT32       OpensslProxy_SockEventDel(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex)
{
    PPERSOCKINFO_S pstPeerSockInfo = NULL;
    INT32  iPeerIndex = 0;

    if (NULL == pstSockMgr
        || uiEvtIndex >= WSAEVT_NUMS )
    {
        return SYS_ERR;
    }

    if ( INVALID_SOCKET != pstSockMgr->stArrySockInfo[uiEvtIndex].sSockfd )
    {
        /*保存对端的*/
        iPeerIndex = OpensslProxy_GetPeerSockEventIndex(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
        
        /*1. 先处理本身的Socket*/
        OpensslProxy_PerSockEventClear(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
       /*移除相关事件*/
       WSACloseEvent(pstSockMgr->stNetEvent.arrWSAEvts[uiEvtIndex]);
       /*重置一下*/
       OpensslProxy_PerSockInfoReset(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
       /*清空事件*/
       OpensslProxy_NetworkEventReset(pstSockMgr, uiEvtIndex);

       InterlockedDecrement(&pstSockMgr->ulSockNums);

        /*然后通知对端的socket进行关闭处理*/
       if ( iPeerIndex > 0 
           && iPeerIndex < WSAEVT_NUMS )
       {
           pstPeerSockInfo = &pstSockMgr->stArrySockInfo[iPeerIndex];
           /*对端可能已经被释放了，需要判断有效性*/
           if ( NULL != pstPeerSockInfo 
               && pstPeerSockInfo->lEvtsIndex > 0
               && pstPeerSockInfo->sSockfd != INVALID_SOCKET )
           {
               /*通知对端也进行关闭*/
               (VOID)pstPeerSockInfo->pfSockCtrlCb(pstSockMgr, iPeerIndex, SOCKCTRL_SHUTDOWN);
           }
       }
    }
    
    return SYS_OK;
}


SOCK_MGR_S *OpensslProxy_SockMgrCreate(WORKER_CTX_S *pstWorker, UINT32   uiArryIndex)
{
    SOCK_MGR_S      *pstSockMgr  = NULL;
    DWORD				 dwStatckSize = MGR_STACKSIZE;
    ULONG                 ulBlock = 1;
    INT32                   iRet = 0;

    pstSockMgr = (SOCK_MGR_S *)malloc(sizeof(SOCK_MGR_S));
    if (NULL == pstSockMgr)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "malloc socket manager context error!");
        return NULL;
    }

    RtlZeroMemory(pstSockMgr, sizeof(SOCK_MGR_S));
    pstSockMgr->iErrorCode = MGR_ERRCODE_SUCCESS;
    pstSockMgr->uiArryIndex = uiArryIndex;

    for ( int index =0; index< WSAEVT_NUMS; index++ )
    {
        OpensslProxy_PerSockInfoReset(&pstSockMgr->stArrySockInfo[index]);
        OpensslProxy_NetworkEventReset(pstSockMgr, index);
    }

    pstSockMgr->hCompleteEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (NULL == pstSockMgr->hCompleteEvent)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Dispatch ctx create complete event error!");
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }

    /*创建UDP通信端口*/
    pstSockMgr->sUdpMsgSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == pstSockMgr->sUdpMsgSock)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg udp socket create error=%d", GetLastError());
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }

    iRet = ioctlsocket(pstSockMgr->sUdpMsgSock, FIONBIO, (unsigned long *)&ulBlock);//设置成非阻塞模式。  
    if (iRet == SOCKET_ERROR)//设置失败。
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Set ioctrl fionbio error=%d\n", WSAGetLastError());
        closesocket(pstSockMgr->sUdpMsgSock);
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }

    /*添加消息socket到本网络事件中进行处理*/
    if ( SYS_ERR == OpensslProxy_SockEventAdd(pstSockMgr,  pstSockMgr->sUdpMsgSock, SOCKTYPE_MSG) )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Add socket network event error=%d\n", WSAGetLastError());
        closesocket(pstSockMgr->sUdpMsgSock);
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }
    else
    {
        InterlockedIncrement(&pstSockMgr->ulSockNums);
    }

    /*直接在当前线程先创建Accept的本地服务端*/
    pstSockMgr->hThreadHandle = _beginthreadex(NULL, dwStatckSize, OpensslProxy_NetworkEventsWorker, pstSockMgr, 0, NULL);

    WaitForSingleObject(pstSockMgr->hCompleteEvent, INFINITE);

    /*表示线程初始化过程中存在问题，直接退出*/
    if (pstSockMgr->iErrorCode != MGR_ERRCODE_SUCCESS)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Socker Network Event pthread create error,  errorCode=%d", pstSockMgr->iErrorCode);
        closesocket(pstSockMgr->sUdpMsgSock);
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }


    return pstSockMgr;
}

VOID OpensslProxy_SockMgrRelease(SOCK_MGR_S *pstSockMgr)
{
    if (NULL != pstSockMgr)
    {
        free(pstSockMgr);
    }
}

WORKER_CTX_S *OpensslProxy_NetworkEventWorkerCreate()
{
	WORKER_CTX_S *pstWorker = NULL;
    UINT32                uiIndex = 0;

	pstWorker = (WORKER_CTX_S *)malloc(sizeof(WORKER_CTX_S));
	if (NULL == pstWorker)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "malloc worker context error!");
		return NULL;
	}

	RtlZeroMemory(pstWorker, sizeof(WORKER_CTX_S));
    InitializeCriticalSection(&pstWorker->stWorkerLock);

    for (int i = 0; i < MGR_ARRYNUMS; i++)
    {
        pstWorker->pstArryWorker[i] = NULL;
    }

    pstWorker->uiWorkerNums = MSG_UDPPORT_START;

    /*默认先创建一个*/
    pstWorker->pstArryWorker[uiIndex] = OpensslProxy_SockMgrCreate(pstWorker, uiIndex);
    if (NULL == pstWorker->pstArryWorker[uiIndex] )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "create socket manager error!");
        DeleteCriticalSection(&pstWorker->stWorkerLock);
        free(pstWorker);
        return NULL;
    }



	return pstWorker;
}


VOID OpensslProxy_NetworkEventWorkerRelease(PWORKER_CTX_S pstWorker)
{
	if (NULL != pstWorker)
	{
        for (int i = 0; i < MGR_ARRYNUMS; i++)
        {
            OpensslProxy_SockMgrRelease(pstWorker->pstArryWorker[i]);
        }

        DeleteCriticalSection(&pstWorker->stWorkerLock);
		free(pstWorker);
	}
}








