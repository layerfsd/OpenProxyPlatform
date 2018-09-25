
#include <openssl\ssl.h>
#include <openssl/err.h>  
#include <openssl/x509.h>  

#define				SSLTYPE_UNKNOW	0
#define				SSLTYPE_CLIENT		1
#define				SSLTYPE_SERVER		2

typedef enum
{
	TLSVERSION_INIT = 0,				/*未判断的初始化状态*/
	TLSVERSION_NOTSSL,				/*不是SSL加密*/
	TLSVERSION_1_0,						/*TLSV1.0版本*/
	TLSVERSION_1_1,						/*TLSV1.1版本*/
	TLSVERSION_1_2,						/*TLSV1.2版本*/
	TLSVERSION_1_3,						/*TLSV1.3版本*/
}TLSVERSION_E;;


/*SOCKET业务类型*/
typedef enum
{
    SOCKTYPE_UNKNOW=0,
	SOCKTYPE_MSG,		        /*线程间通信*/
	SOCKTYPE_LOCAL,			/*本地Socket*/
	SOCKTYPE_PROXY,			/*代理Socket*/

	SOCKTYPE_NUMS
}SOCKTYPE_E;

typedef enum
{
    SOCKCTRL_UNKNOW=0,
    SOCKCTRL_CLOSE_RECV,    /*关闭接收*/
    SOCKCTRL_CLOSE_SEND,    /*关闭发送*/
    SOCKCTRL_OPEN_RECV,
    SOCKCTRL_OPEN_SEND,
    SOCKCTRL_SHUTDOWN,      /*关闭连接*/

    SOCKCTRL_NUMS
}SOCKCTRL_CODE_E;

/*开始的UDP消息端口*/
#define         MSG_UDPPORT_START       12000

typedef struct tagPerSockInfo		PERSOCKINFO_S, *PPERSOCKINFO_S;
typedef struct tagSocketMgr		SOCK_MGR_S, *PSOCK_MGR_S;
typedef struct tagPerSockTlsInfo SOCK_TLSINFO_S, *PSOCK_TLSINFO_S;

typedef INT32(*PFSOCKCTRLCB)(SOCK_MGR_S *pstSockMgr, UINT32 uiIndex, UINT32 uiCtrlCode);

struct tagPerSockTlsInfo
{
	BOOLEAN			IsSslConnected;
	UINT32				uiSslType;
	UINT32				uiTlsVersion;
	SSL					   *pstSsl;
};
/*通过链表的方式进行管理*/
/*在Worker和Handler的WSAEvent中，都需要使用*/
struct tagPerSockInfo
{
	LIST_ENTRY						stNode;					/*节点*/
	SOCKTYPE_E						eSockType;				/*Socket业务类型*/
    SOCKET		                    sSockfd;			        /*Socket*/
    HANDLE		                    hEvtHandle;				/*事件句柄*/
	LONG							    lEvtsIndex;				/*本身所在的Evts的数组索引*/
	LONG							    lPeerEvtsIndex;			/*因为当前代理设计上规定是成对出现的，所以必然有一个对端的索引*/
	LIST_ENTRY						stIoBufList;				/*包顺序链表: 包含了数据包和控制包，按序存放，保持连接本身的传输一致性*/
	PFSOCKCTRLCB				pfSockCtrlCb;			/*本Socket的控制接口，错误关闭，或者是被动的调用*/
	BOOLEAN						bIsTls;						/*是否加密*/
	SOCK_TLSINFO_S				stTlsInfo;					/*TLS的信息*/
};

/*网络触发事件*/
typedef struct tagSockNetworkEvent
{
	WSAEVENT		arrWSAEvts[WSAEVT_NUMS];				/*当前的socket事件数组*/
	SOCKET			arrSocketEvts[WSAEVT_NUMS];			/*事件对应的socket索引*/
}SOCK_NEVET_S, *PSOCK_NEVET_S;

/*WSAEvent线程的socket管理器，Worker和Handler都会使用*/
/*每个线程都有该管理器*/
struct tagSocketMgr
{
    uintptr_t				hThreadHandle;								/*线程句柄*/
    HANDLE				hCompleteEvent;		                        /*完成事件*/
    INT32                   iErrorCode;										/*线程错误码*/
	UINT32				uiArryIndex;							            /*所在管理器数组索引, 找原来的线程时候需要*/
	SOCKET				sUdpMsgSock;									/*简单通信的FD, 本地消息端口矩阵,  直接用UDP通信, 仅用于少量消息的线程间通信(大量时会不可靠)*/
    USHORT              usUdpMsgPort;									/*本线程的通信端口*/
    PERSOCKINFO_S	stArrySockInfo[WSAEVT_NUMS];		/*管理的Socket信息， 通过索引管理，这样就可以和网络事件复用相同索引，提高查找效率*/
	SOCK_NEVET_S	stNetEvent;										/*网络触发事件*/
	ULONG				ulSockNums;									/*当前有没有超过64-4个就可以了, 一个用作通信了, 然后保持成对*/
};


