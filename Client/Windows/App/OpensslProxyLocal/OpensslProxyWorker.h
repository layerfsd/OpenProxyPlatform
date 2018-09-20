#pragma once

typedef struct tagWorkerContext
{
	PSOCK_MGR_S				pstArryWorker[MGR_ARRYNUMS];		/*�����߳��������*/
    UINT32                            usMsgPortNum;                                  /*ͨ�Ŷ˿ڵļ����������ظ�*/
	UINT32							uiWorkerNums;									/*�������̸߳���*/
    SOCKET                           sMsgCtrlSockFd;                                  /*�ڲ���Ϣ����Socket*/
	CRITICAL_SECTION			stWorkerLock;										/*ͳһ��*/
}WORKER_CTX_S, *PWORKER_CTX_S;

WORKER_CTX_S *OpensslProxy_NetworkEventWorkerCreate();

VOID    OpensslProxy_NetworkEventWorkerRelease(PWORKER_CTX_S pstWorker);

INT32   OpensslProxy_DispatchNetworkByBlanceAlgm(SOCKET sNewClientFd, UINT32 uiBlanceAlgm);


