#pragma once

#define         MCTL_BUFSIZE            1024
#define         MCTL_BODYSIZE         786
/**/
typedef enum
{
    MCTRL_MSGCODE_UNKNOW = 0,
    MCTRL_MSGCODE_CLIENTINFO,

    MCTRL_MSGCODE_NUMS
}MCTRL_CODE_E;

typedef struct tagMessageCtrlTlv
{
    UINT32  uiMsgCode;
    UINT32  uiLength;
    CHAR    acMessage[MCTL_BODYSIZE];
}MCTRL_TLV_S, *PMCTRL_TLV_S;


INT32 OpensslProxy_MessageCtrlMain(VOID *pvCtx, CHAR *acBuf, UINT32 uiLen);


/*关于Socket的控制*/
typedef enum
{
    CLNTNFO_CTRLCODE_UNKNOW = 0,
    CLNTNFO_CTRLCODE_SOCKADD,
    CLNTNFO_CTRLCODE_SOCKDEL,

    CLNTNFO_CTRLCODE_NUMS
}CLIENT_CTRLCODE_E;
typedef struct tagMessageCtrlClientInfo
{
    UINT32      uiCtrlCode;
    SOCKET      sClientSockfd;

}MCTRL_CLIENTINFO_S, *PMCTRL_CLIENTINFO_S;

INT32 OpensslProxy_MessageCtrl_ClientInfo(CHAR *pcSndBuf, PMCTRL_CLIENTINFO_S pstClientInfo);



