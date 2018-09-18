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




WORKER_CTX_S *OpensslProxy_NetworkEventWorkerCreate()
{
	WORKER_CTX_S *pstWorker = NULL;

	pstWorker = (WORKER_CTX_S *)malloc(sizeof(WORKER_CTX_S));
	if (NULL == pstWorker)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "malloc worker context error!\n");
		return NULL;
	}

	RtlZeroMemory(pstWorker, sizeof(WORKER_CTX_S));


	return pstWorker;
}


VOID OpensslProxy_NetworkEventWorkerRelease(PWORKER_CTX_S pstWorker)
{
	if (NULL == pstWorker)
	{
		free(pstWorker);
	}
}








