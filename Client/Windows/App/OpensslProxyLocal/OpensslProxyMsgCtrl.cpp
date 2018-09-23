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
#include "OpensslProxyMsgCtrl.h"
#include "OpensslProxyTlsHandler.h"
#include "OpensslProxyWorker.h"




INT32 OpensslProxy_MessageCtrlMain(VOID *pvCtx, CHAR *acBuf, UINT32 uiLen)
{
	PMCTRL_TLV_S               pstTlv = NULL;

	if ( NULL == acBuf
		|| uiLen != MCTL_BUFSIZE )
	{
		return SYS_ERR;
	}

	pstTlv = (PMCTRL_TLV_S)acBuf;

	switch (pstTlv->uiMsgCode)
	{
		case MCTRL_MSGCODE_CLIENTINFO:
			{
				PMCTRL_CLIENTINFO_S pstSnd = (PMCTRL_CLIENTINFO_S)pstTlv->acMessage;
				SOCK_MGR_S*				  pstSockMgr = (SOCK_MGR_S*)pvCtx;

				/*��ӱ��صĿͻ�����Ϣ*/
				if ( SYS_ERR == OpensslProxy_SockEventAdd(pstSockMgr, pstSnd->sClientSockfd, SOCKTYPE_LOCAL) )
				{
					return SYS_ERR;
				}
				else
				{

				}
			}
			break;
		default:

			break;
	}
    return SYS_OK;
}


/*��Ϣ��֧�ӿ�*/
INT32 OpensslProxy_MessageCtrl_ClientInfo(CHAR *pcSndBuf, PMCTRL_CLIENTINFO_S pstClientInfo)
{
    PMCTRL_TLV_S               pstTlv   = NULL;
    PMCTRL_CLIENTINFO_S pstSnd  = NULL;

    if (NULL == pcSndBuf 
        || NULL == pstClientInfo 
        )
    {
        return SYS_ERR;
    }

    pstTlv = (PMCTRL_TLV_S)pcSndBuf;
    pstTlv->uiMsgCode = MCTRL_MSGCODE_CLIENTINFO;
    pstTlv->uiLength = sizeof(MCTRL_CLIENTINFO_S);
    
    pstSnd = (PMCTRL_CLIENTINFO_S)pstTlv->acMessage;
    pstSnd->uiCtrlCode = pstClientInfo->uiCtrlCode;
    pstSnd->sClientSockfd = pstClientInfo->sClientSockfd;

    /*һ����˵�����������Ҫ���ط��͵ĳ��ȣ�������Ϊ�򵥣����ǲ������������ж�*/
    return SYS_OK;
}
