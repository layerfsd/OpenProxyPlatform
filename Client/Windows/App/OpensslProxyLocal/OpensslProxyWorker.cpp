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

/*��ȡ�Զ˵��¼�����*/
INT32    OpensslProxy_GetPeerSockEventIndex(PERSOCKINFO_S *pstPerSockInfo)
{
    return pstPerSockInfo->lPeerEvtsIndex;
}

VOID       OpensslProxy_PerSockEventClear(PERSOCKINFO_S *pstPerSockInfo)
{
    /*ֱ�Ӽ���ͷŵ����еı�Socket���IoBuf��Դ*/
    COMM_IOBUF_BufListRelease(&pstPerSockInfo->stIoBufList);

    /*�ȹرձ�socket��������Դ*/
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

    /*��ʼ���б������붯��*/
    for (int iIndex = 0; iIndex < WSAEVT_NUMS; iIndex++)
    {
        if ( INVALID_SOCKET == pstSockMgr->stArrySockInfo[iIndex].sSockfd )
        {
            /*ȷ��û���������������*/
            InitializeListHead(&pstSockMgr->stArrySockInfo[iIndex].stIoBufList);
            pstSockMgr->stArrySockInfo[iIndex].eSockType = (SOCKTYPE_E)uiSockType;
            pstSockMgr->stArrySockInfo[iIndex].lEvtsIndex = iIndex;
            pstSockMgr->stArrySockInfo[iIndex].sSockfd = sSocketFd;
            pstSockMgr->stArrySockInfo[iIndex].hEvtHandle = WSACreateEvent();

            /*��ӵ���Ӧ�������¼�*/
            pstSockMgr->stNetEvent.arrSocketEvts[iIndex] = sSocketFd;
            pstSockMgr->stNetEvent.arrWSAEvts[iIndex] = pstSockMgr->stArrySockInfo[iIndex].hEvtHandle;
            WSAEventSelect(sSocketFd, pstSockMgr->stNetEvent.arrWSAEvts[iIndex], FD_READ | FD_CLOSE);

            InterlockedIncrement(&pstSockMgr->ulSockNums);
            return SYS_OK;
        }
    }

    return SYS_ERR;
}

/*ɾ���������¼���ע�⣺ ȷ����ɾ��֮ǰ�����Զ�Ҳɾ��*/
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
        /*����Զ˵�*/
        iPeerIndex = OpensslProxy_GetPeerSockEventIndex(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
        
        /*1. �ȴ������Socket*/
        OpensslProxy_PerSockEventClear(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
       /*�Ƴ�����¼�*/
       WSACloseEvent(pstSockMgr->stNetEvent.arrWSAEvts[uiEvtIndex]);
       /*����һ��*/
       OpensslProxy_PerSockInfoReset(&pstSockMgr->stArrySockInfo[uiEvtIndex]);
       /*����¼�*/
       OpensslProxy_NetworkEventReset(pstSockMgr, uiEvtIndex);

       InterlockedDecrement(&pstSockMgr->ulSockNums);

        /*Ȼ��֪ͨ�Զ˵�socket���йرմ���*/
       if ( iPeerIndex > 0 
           && iPeerIndex < WSAEVT_NUMS )
       {
           pstPeerSockInfo = &pstSockMgr->stArrySockInfo[iPeerIndex];
           /*�Զ˿����Ѿ����ͷ��ˣ���Ҫ�ж���Ч��*/
           if ( NULL != pstPeerSockInfo 
               && pstPeerSockInfo->lEvtsIndex > 0
               && pstPeerSockInfo->sSockfd != INVALID_SOCKET )
           {
               /*֪ͨ�Զ�Ҳ���йر�*/
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

    /*����UDPͨ�Ŷ˿�*/
    pstSockMgr->sUdpMsgSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == pstSockMgr->sUdpMsgSock)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg udp socket create error=%d", GetLastError());
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }

    iRet = ioctlsocket(pstSockMgr->sUdpMsgSock, FIONBIO, (unsigned long *)&ulBlock);//���óɷ�����ģʽ��  
    if (iRet == SOCKET_ERROR)//����ʧ�ܡ�
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Set ioctrl fionbio error=%d\n", WSAGetLastError());
        closesocket(pstSockMgr->sUdpMsgSock);
        CloseHandle(pstSockMgr->hCompleteEvent);
        free(pstSockMgr);
        pstSockMgr = NULL;
        return NULL;
    }

    /*�����Ϣsocket���������¼��н��д���*/
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

    /*ֱ���ڵ�ǰ�߳��ȴ���Accept�ı��ط����*/
    pstSockMgr->hThreadHandle = _beginthreadex(NULL, dwStatckSize, OpensslProxy_NetworkEventsWorker, pstSockMgr, 0, NULL);

    WaitForSingleObject(pstSockMgr->hCompleteEvent, INFINITE);

    /*��ʾ�̳߳�ʼ�������д������⣬ֱ���˳�*/
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

    /*Ĭ���ȴ���һ��*/
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








