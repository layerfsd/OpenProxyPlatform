#pragma once

typedef struct tagWorkerContext
{
	PSOCK_MGR_S					pstArryWorker[MGR_ARRYNUMS];		 /*工作线程最大数量*/
    UINT32                            usMsgPortNum;                                   /*通信端口的计数，避免重复*/
	UINT32							uiWorkerNums;									 /*工作的线程个数*/
    SOCKET                           sMsgCtrlSockFd;                                   /*内部消息控制Socket*/
    USHORT                          sMsgUdpPort;                                      /*内部消息控制Socket*/
	CRITICAL_SECTION			stWorkerLock;										 /*统一锁*/
}WORKER_CTX_S, *PWORKER_CTX_S;

WORKER_CTX_S *OpensslProxy_NetworkEventWorkerCreate();

VOID        OpensslProxy_NetworkEventWorkerRelease();

INT32       OpensslProxy_DispatchNetworkByBlanceAlgm(SOCKET sNewClientFd, UINT32 uiBlanceAlgm);

INT32       OpensslProxy_SockMgr_MainWorkerSendto(CHAR *pcSndBuf, UINT32 uiSendLen, UINT32 uiArryIndex);

INT32       OpensslProxy_PerSockEventDel(SOCK_MGR_S *pstSockMgr, UINT32 uiEvtIndex);

INT32       OpensslProxy_PerSockEventAdd(SOCK_MGR_S *pstSockMgr, SOCKET sSocketFd, UINT32 uiSockType);



