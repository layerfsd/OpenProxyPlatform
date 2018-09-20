
/*SOCKETҵ������*/
typedef enum
{
    SOCKTYPE_UNKNOW=0,
	SOCKTYPE_MSG,		        /*�̼߳�ͨ��*/
	SOCKTYPE_LOCAL,			/*����Socket*/
	SOCKTYPE_PROXY,			/*����Socket*/

	SOCKTYPE_NUMS
}SOCKTYPE_E;

typedef enum
{
    SOCKCTRL_UNKNOW=0,
    SOCKCTRL_CLOSE_RECV,    /*�رս���*/
    SOCKCTRL_CLOSE_SEND,    /*�رշ���*/
    SOCKCTRL_OPEN_RECV,
    SOCKCTRL_OPEN_SEND,
    SOCKCTRL_SHUTDOWN,      /*�ر�����*/

    SOCKCTRL_NUMS
}SOCKCTRL_CODE_E;

/*��ʼ��UDP��Ϣ�˿�*/
#define         MSG_UDPPORT_START       12000

typedef struct tagPerSockInfo  PERSOCKINFO_S, *PPERSOCKINFO_S;
typedef struct tagSocketMgr SOCK_MGR_S, *PSOCK_MGR_S;

typedef INT32(*PFSOCKCTRLCB)(SOCK_MGR_S *pstSockMgr, UINT32 uiIndex, UINT32 uiCtrlCode);

/*ͨ������ķ�ʽ���й���*/
/*��Worker��Handler��WSAEvent�У�����Ҫʹ��*/
struct tagPerSockInfo
{
	LIST_ENTRY						stNode;					/*�ڵ�*/
	SOCKTYPE_E					eSockType;				/*Socketҵ������*/
    SOCKET		                    sSockfd;			        /*Socket*/
    HANDLE		                    hEvtHandle;				/*�¼����*/
	LONG							    lEvtsIndex;				/*�������ڵ�Evts����������*/
	LONG							    lPeerEvtsIndex;		/*��Ϊ��ǰ��������Ϲ涨�ǳɶԳ��ֵģ����Ա�Ȼ��һ���Զ˵�����*/
	LIST_ENTRY						stIoBufList;				/*��˳������: ���������ݰ��Ϳ��ư��������ţ��������ӱ���Ĵ���һ����*/
	PFSOCKCTRLCB				pfSockCtrlCb;			/*��Socket�Ŀ��ƽӿڣ�����رգ������Ǳ����ĵ���*/
};

/*���紥���¼�*/
typedef struct tagSockNetworkEvent
{
	WSAEVENT		arrWSAEvts[WSAEVT_NUMS];				/*��ǰ��socket�¼�����*/
	SOCKET			arrSocketEvts[WSAEVT_NUMS];			/*�¼���Ӧ��socket����*/
}SOCK_NEVET_S, *PSOCK_NEVET_S;

/*WSAEvent�̵߳�socket��������Worker��Handler����ʹ��*/
/*ÿ���̶߳��иù�����*/
struct tagSocketMgr
{
    uintptr_t				hThreadHandle;								/*�߳̾��*/
    HANDLE				hCompleteEvent;		                        /*����¼�*/
    INT32                   iErrorCode;                                     /*�̴߳�����*/
	UINT32				uiArryIndex;							            /*���ڹ�������������, ��ԭ�����߳�ʱ����Ҫ*/
	SOCKET				sUdpMsgSock;									/*��ͨ�ŵ�FD, ������Ϣ�˿ھ���,  ֱ����UDPͨ��, ������������Ϣ���̼߳�ͨ��(����ʱ�᲻�ɿ�)*/
    PERSOCKINFO_S	stArrySockInfo[WSAEVT_NUMS];	/*�����Socket��Ϣ�� ͨ���������������Ϳ��Ժ������¼�������ͬ��������߲���Ч��*/
	SOCK_NEVET_S	stNetEvent;										/*���紥���¼�*/
	ULONG				ulSockNums;									/*��ǰ��û�г���64-4���Ϳ�����, һ������ͨ����, Ȼ�󱣳ֳɶ�*/
};


