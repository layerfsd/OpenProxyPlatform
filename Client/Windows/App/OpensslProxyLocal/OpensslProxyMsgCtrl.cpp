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




INT32 OpensslProxy_MessageCtrlMain(CHAR *acBuf, UINT32 uiLen)
{


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
