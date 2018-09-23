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
#include "OpensslProxyTlsHandler.h"
#include "OpensslProxyWorker.h"
#include "OpensslProxyPacketDispatch.h"
#include "OpenSSLProxyMgr.h"
#include "OpensslProxyMsgCtrl.h"


/******************************************PerSocket����Ϣ********************************************************/
/*Ϊ�˽��������߳���Ϣ��������ʣ��޸�Ϊȫ�ֱ���*/
WORKER_CTX_S *g_pstWorker = NULL;

unsigned int __stdcall OpensslProxy_NetworkEventsWorker(void *pvArgv)
{
    ULONG                    ulArrayIndex = 0;
    INT32                       iRet = 0;
    INT32                       iEvtIndex = 0;
    INT32                       iError = 0;
    SOCKET                    sSocket = INVALID_SOCKET;
    SOCK_MGR_S*         pstSockMgr = NULL;
	PPERSOCKINFO_S	pstPerSockInfo = NULL;
    CHAR                       acRecvBuf[MSG_RECVBUF] = {0};
    struct  sockaddr_in  stClientInfo = { 0 };
    WSANETWORKEVENTS NetworkEvents = { 0 };
	SSL_CTX*					pstTlsCtxClient = NULL;
	SSL_CTX*					pstTlsCtxServer = NULL;
	INT32                       iLen = sizeof(stClientInfo);

    if (NULL == pvArgv)
    {
        return -1;
    }

    pstSockMgr = (SOCK_MGR_S *)pvArgv;

	pstTlsCtxClient = SSL_CTX_new(SSLv23_client_method());
	if (NULL == pstTlsCtxClient)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL Ctx client create error!\n");
		return -1;
	}

	pstTlsCtxServer = SSLPROXY_TLSCtxNewServer();
	if (NULL == pstTlsCtxServer)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL Ctx client create error!\n");
		SSL_CTX_free(pstTlsCtxClient);
		pstTlsCtxClient = NULL;
		return -1;
	}

    SetEvent(pstSockMgr->hCompleteEvent);

    while (TRUE)
    {
        iRet = WSAWaitForMultipleEvents(pstSockMgr->ulSockNums, pstSockMgr->stNetEvent.arrWSAEvts, FALSE, INFINITE, FALSE);
        if ( iRet == WSA_WAIT_FAILED || iRet == WSA_WAIT_TIMEOUT)
        {
            iError = GetLastError();
            if ( iError != ERROR_INVALID_PARAMETER )
            {
                CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "WSAEvent continue, iRet=%d errorcode=(%d), sockNums=%d\n",
                    iRet, iError, pstSockMgr->ulSockNums);
            }
            continue;
        }

        iEvtIndex = iRet - WSA_WAIT_EVENT_0;
        sSocket   = pstSockMgr->stNetEvent.arrSocketEvts[iEvtIndex];

        WSAEnumNetworkEvents(sSocket, pstSockMgr->stNetEvent.arrWSAEvts[iEvtIndex], &NetworkEvents);

        if (NetworkEvents.lNetworkEvents & FD_READ)
        {
            /*��Ϣ����*/
            if (sSocket == pstSockMgr->sUdpMsgSock )
            {
                iRet = recvfrom(sSocket, acRecvBuf, MSG_RECVBUF, 0, (struct sockaddr*)&stClientInfo, &iLen);
                if (iRet > 0 )
                {
                    if (SYS_ERR == OpensslProxy_MessageCtrlMain(pstSockMgr, acRecvBuf, iRet))
                    {
                        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "MessageCtrlMain handler error, iRet=%d errorcode=(%d)\n", iRet, GetLastError() );
                    }
                }
                else
                {
                    CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "MessageCtrlMain udp recvfrom error, iRet=%d errorcode=(%d)\n", iRet, GetLastError());
                }
            }
            else
            {
				pstPerSockInfo = &pstSockMgr->stArrySockInfo[iEvtIndex];

				/*��������������ص�Socket*/
				if ( pstPerSockInfo->eSockType == SOCKTYPE_LOCAL )
				{
					/*����Ǳ��صĸոտ�ʼ���շ�����Ҫ���жϱ����Ƿ�ΪTLS*/
					if ( TLSVERSION_INIT == pstPerSockInfo->stTlsInfo.uiTlsVersion )
					{
						pstPerSockInfo->stTlsInfo.uiTlsVersion = SSLPROXY_TLSVersionProtoCheck(pstPerSockInfo->sSockfd);
						if (TLSVERSION_NOTSSL != pstPerSockInfo->stTlsInfo.uiTlsVersion)
						{
							pstPerSockInfo->bIsTls = TRUE;
						}
						else
						{
							pstPerSockInfo->bIsTls = FALSE;
						}
					}

					/*���ܴ�������*/
					if (pstPerSockInfo->bIsTls)
					{
						/*�Ƿ��Ѿ����ӳɹ�*/
						if (TRUE == pstPerSockInfo->stTlsInfo.IsSslConnected)
						{

						}
					}
					else
					/*�Ǽ��ܵĴ�������*/
					{
						iRet = recv(sSocket, acRecvBuf, MSG_RECVBUF, 0);
						if (iRet == 0 || (iRet == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET))
						{
							CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "WSAEnumNetworkEvents error, iRet=%d errorcode=(%d)\n", iRet, iError);
							(VOID)OpensslProxy_SockEventDel(pstSockMgr, iEvtIndex);
						}
						else
						{
							printf("[LOCAL!] Read the Content=%s,\n", acRecvBuf);
						}
					}
				}
				else if (pstPerSockInfo->eSockType ==  SOCKTYPE_PROXY )
				{

				}
				else
				{

				}
            }
        }

        if (NetworkEvents.lNetworkEvents & FD_CLOSE)
        {
            
        }

    }

    return 0;
}

VOID   OpensslProxy_NetworkEventReset(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex)
{
    if (uiEvtIndex >= WSAEVT_NUMS)
    {
        return;
    }
    pstSockMgr->stNetEvent.arrWSAEvts[uiEvtIndex] = NULL;
    pstSockMgr->stNetEvent.arrSocketEvts[uiEvtIndex] = INVALID_SOCKET;
}

INT32 OpensslProxy_SockEventCtrl(SOCK_MGR_S *pstSockMgr, UINT32 uiIndex, UINT32 uiCtrlCode)
{
    /*TODO: �����ʵӦ������Ҫ��ȡԭ�ȵģ�Ȼ��ȡ������������λ*/
    ULONG   ulEventMask = 0;

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
            ulEventMask = FD_CLOSE;
            break;
        case SOCKCTRL_OPEN_RECV:
            ulEventMask = FD_READ | FD_CLOSE;
            break;
        case SOCKCTRL_CLOSE_SEND:
            ulEventMask =  FD_CLOSE;
            break;
        case SOCKCTRL_OPEN_SEND:
            ulEventMask = FD_WRITE | FD_CLOSE;
            break;
        case SOCKCTRL_UNKNOW:
        default:
            break;
    }

    WSAEventSelect(pstSockMgr->stArrySockInfo[uiIndex].sSockfd, pstSockMgr->stArrySockInfo[uiIndex].hEvtHandle, ulEventMask);

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

			/*SSL���*/
			pstSockMgr->stArrySockInfo[iIndex].bIsTls = FALSE;
			pstSockMgr->stArrySockInfo[iIndex].stTlsInfo.IsSslConnected = FALSE;
			pstSockMgr->stArrySockInfo[iIndex].stTlsInfo.pstSsl = NULL;
			pstSockMgr->stArrySockInfo[iIndex].stTlsInfo.uiSslType = SSLTYPE_UNKNOW;
			pstSockMgr->stArrySockInfo[iIndex].stTlsInfo.uiTlsVersion = TLSVERSION_INIT;

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

/*��ȡͨ�Ŷ˿�*/
USHORT  OpensslProxy_GetMsgSocketPortByIndex(UINT32   uiArryIndex)
{
    USHORT  usPort = 0;

    if (NULL == g_pstWorker
        || uiArryIndex >= MGR_ARRYNUMS )
    {
        return 0;
    }

    /*���߳���*/
    EnterCriticalSection(&g_pstWorker->stWorkerLock);
    if (NULL != g_pstWorker->pstArryWorker[uiArryIndex] )
    {
        usPort = g_pstWorker->pstArryWorker[uiArryIndex]->usUdpMsgPort;
    }
    LeaveCriticalSection(&g_pstWorker->stWorkerLock);
    
    return usPort;
}


/*��ȡͨ�Ŷ˿�*/
USHORT  OpensslProxy_GenMsgSocketPort()
{
    USHORT  usPort = 0;

    if (NULL == g_pstWorker )
    {
        return 0;
    }

    /*ֱ�ӻ����߳�����*/
    EnterCriticalSection(&g_pstWorker->stWorkerLock);
    InterlockedIncrement(&g_pstWorker->usMsgPortNum);
    usPort = g_pstWorker->usMsgPortNum;
    LeaveCriticalSection(&g_pstWorker->stWorkerLock);

    return usPort;
}

/*ֱ������ص������̷߳�����Ϣ*/
INT32 OpensslProxy_SockMgr_MainWorkerSendto(CHAR *pcSndBuf, UINT32 uiSendLen,  UINT32 uiArryIndex)
{
    USHORT          usPort = 0;
    INT32              iRet = 0;
    SOCKET          sSocket = INVALID_SOCKET;
    sockaddr_in    remoteAddr = {0};
    int                   nAddrLen = sizeof(remoteAddr);

    usPort = OpensslProxy_GetMsgSocketPortByIndex(uiArryIndex);
    if (0 == usPort)
    {
        return SYS_ERR;
    }

    /*����UDPͨ�Ŷ˿�*/
    sSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == sSocket)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Director message udp socket error=%d", GetLastError());
        return SYS_ERR;
    }

    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(usPort);
    inet_pton(AF_INET, MGR_LOCALADDRA, &remoteAddr.sin_addr);

    iRet = sendto(sSocket, pcSndBuf, uiSendLen,0, (sockaddr *)&remoteAddr, nAddrLen);
    if (iRet <= 0 )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Director message udp socket sendto error=%d", GetLastError());
        return SYS_ERR;
    }

    return SYS_OK;
}

SOCK_MGR_S *OpensslProxy_SockMgrCreate(WORKER_CTX_S *pstWorker, UINT32   uiArryIndex)
{
    SOCK_MGR_S*          pstSockMgr  = NULL;
    SOCKADDR_IN         stSerAddr = { 0 };
    DWORD				     dwStatckSize = MGR_STACKSIZE;
    ULONG                    ulBlock = 1;
    INT32                       iRet = 0;

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

    pstSockMgr->usUdpMsgPort = OpensslProxy_GenMsgSocketPort();

    stSerAddr.sin_family = AF_INET;
    stSerAddr.sin_port = htons(pstSockMgr->usUdpMsgPort);
    inet_pton(AF_INET, MGR_LOCALADDRA, &stSerAddr.sin_addr);

    //stSerAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    if (bind(pstSockMgr->sUdpMsgSock, (sockaddr *)&stSerAddr, sizeof(stSerAddr)) == SOCKET_ERROR)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg udp socket bind error=%d", GetLastError());
        closesocket(pstSockMgr->sUdpMsgSock); 
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

    /*�����߳�Ҳ��Ҫ����*/
    InterlockedIncrement(&pstWorker->uiWorkerNums);

    return pstSockMgr;
}

VOID OpensslProxy_SockMgrRelease(SOCK_MGR_S *pstSockMgr)
{
    if (NULL != pstSockMgr)
    {
        free(pstSockMgr);
    }
}

/**********************************************Worker�ܵ������ĵĹ�����************************************************************/
/*ȫ�ַ��ʣ�����ֱ�ӷ��ʵ�ͨ��socket*/
/*�����㷨�ɷ���ص�ClientSocket*/
INT32 OpensslProxy_DispatchNetworkByBlanceAlgm(SOCKET sNewClientFd, UINT32 uiBlanceAlgm)
{
    UINT32                              uiArryIndex = 0;
    INT32                                 iRet = 0;
    MCTRL_CLIENTINFO_S      stClientCtrlInfo = {0};
    CHAR                                 acMessageBuf[MCTL_BUFSIZE] = {0};

    /*TODO: �����㷨����ȡ����Ҫ�ַ���Worker�߳�����*/
    switch (uiBlanceAlgm)
    {
        case 0:
            /*Ĭ�Ͼ��ǵ�0��*/
            uiArryIndex = 0;
            break;
        default:
            break;
    }

    stClientCtrlInfo.uiCtrlCode = CLNTNFO_CTRLCODE_SOCKADD;
    stClientCtrlInfo.sClientSockfd = sNewClientFd;

    /*��ȡ�������������Ȼ��ʼ�ͻ�����Ϣ�ַ�*/
    iRet = OpensslProxy_MessageCtrl_ClientInfo(acMessageBuf, &stClientCtrlInfo);
    if ( SYS_ERR == iRet )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg ctrl make pack Info:  [ client info ] error!");
        return SYS_ERR;
    }
    else
    {
        /*���͸��Է�*/
        if (SYS_ERR == OpensslProxy_SockMgr_MainWorkerSendto(acMessageBuf, MCTL_BUFSIZE, uiArryIndex))
        {
            CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg ctrl send pack error!");
            return SYS_ERR;
        }
    }

    return SYS_OK;
}


unsigned int __stdcall OpensslProxy_WorkerMsgCtrl(PVOID pvArg)
{
    WORKER_CTX_S *pstWorker = NULL;
    CHAR                  acMsg[MCTL_BUFSIZE] = {0};
    struct  sockaddr_in stClientInfo = { 0 };
    INT32                   iLen = sizeof(stClientInfo);
    INT32                   iRet = 0;

    if (NULL == pvArg)
    {
        return -1;
    }

    pstWorker = (WORKER_CTX_S *)pvArg;

    while (1)
    {
        RtlZeroMemory(acMsg, MCTL_BUFSIZE);
        iRet = recvfrom(pstWorker->sMsgCtrlSockFd, acMsg, MCTL_BUFSIZE, 0, (struct sockaddr*)&stClientInfo, &iLen);
        if (iRet < 0)
        {
            CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "worker msg ctrl udps recvfrom message error=%08x!", GetLastError());
            break;
        }
        else
        {
            if ( SYS_ERR == OpensslProxy_MessageCtrlMain(pstWorker, acMsg,  iRet) )
            {
                CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "worker msg ctrl udps message handler error!");
            }
        }
    }

    return 0;
}

WORKER_CTX_S *OpensslProxy_NetworkEventWorkerCreate()
{
    UINT32                  uiIndex       = 0;
    USHORT                usPort         = 0;
    SOCKADDR_IN      stSerAddr   = {0};

    g_pstWorker = (WORKER_CTX_S *)malloc(sizeof(WORKER_CTX_S));
	if (NULL == g_pstWorker)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "malloc worker context error!");
		return NULL;
	}

	RtlZeroMemory(g_pstWorker, sizeof(WORKER_CTX_S));
    InitializeCriticalSection(&g_pstWorker->stWorkerLock);

    for (int i = 0; i < MGR_ARRYNUMS; i++)
    {
        g_pstWorker->pstArryWorker[i] = NULL;
    }

    g_pstWorker->uiWorkerNums = MSG_UDPPORT_START;

	SSLPROXY_TlsHandler_EnvInit();

    /*����UDPͨ�Ŷ˿�*/
    g_pstWorker->sMsgCtrlSockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (INVALID_SOCKET == g_pstWorker->sMsgCtrlSockFd)
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg udp socket create error=%d", GetLastError());
        DeleteCriticalSection(&g_pstWorker->stWorkerLock);
        free(g_pstWorker);
        return NULL;
    }

    usPort = OpensslProxy_GenMsgSocketPort();
    stSerAddr.sin_family = AF_INET;
    stSerAddr.sin_port = htons(usPort);
    inet_pton(AF_INET, MGR_LOCALADDRA, &stSerAddr.sin_addr);
    //stSerAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    if ( bind(g_pstWorker->sMsgCtrlSockFd, (sockaddr *)&stSerAddr, sizeof(stSerAddr)) == SOCKET_ERROR )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "msg udp socket bind error=%d", GetLastError());
        closesocket(g_pstWorker->sMsgCtrlSockFd);
        DeleteCriticalSection(&g_pstWorker->stWorkerLock);
        free(g_pstWorker);
        return NULL;
    }

    /*ֱ�Ӵ�����Ϣ�߳�, �򵥵���Ϣ���ƣ����ɿ�����Ҫ��ӿɿ�����*/
    _beginthreadex(NULL, 0, OpensslProxy_WorkerMsgCtrl, g_pstWorker, 0, NULL);

    /*Ĭ���ȴ���һ��*/
    uiIndex = 0;
    g_pstWorker->pstArryWorker[uiIndex] = OpensslProxy_SockMgrCreate(g_pstWorker, uiIndex);
    if (NULL == g_pstWorker->pstArryWorker[uiIndex] )
    {
        CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "create socket manager error!");
        closesocket(g_pstWorker->sMsgCtrlSockFd);
        DeleteCriticalSection(&g_pstWorker->stWorkerLock);
        free(g_pstWorker);
        return NULL;
    }

	return g_pstWorker;
}


VOID OpensslProxy_NetworkEventWorkerRelease()
{
	if (NULL != g_pstWorker)
	{
        for (int i = 0; i < MGR_ARRYNUMS; i++)
        {
            OpensslProxy_SockMgrRelease(g_pstWorker->pstArryWorker[i]);
        }

        DeleteCriticalSection(&g_pstWorker->stWorkerLock);
		free(g_pstWorker);
        g_pstWorker = NULL;
	}
}








