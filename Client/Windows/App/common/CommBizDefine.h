
/*SOCKETҵ������*/
typedef enum
{
	SOCKTYPE_MSG = 0,		/*�̼߳�ͨ��*/
	SOCKTYPE_LOCAL,			/*����Socket*/
	SOCKTYPE_PROXY,			/*����Socket*/

	SOCKTYPE_NUMS
}SOCKTYPE_E;


typedef struct tagSockInfo SOCKINFO_S, *PSOCKINFO_S;

typedef INT32(*PFSOCKCTRLCB)(SOCKINFO_S *pstSockInfo);

/*ͨ������ķ�ʽ���й���*/
/*��Worker��Handler��WSAEvent�У�����Ҫʹ��*/
struct tagSockInfo
{
	LIST_ENTRY						stNode;					/*�ڵ�*/
	SOCKTYPE_E					eSockType;				/*Socketҵ������*/
	SOCKET							sSockfd;					/*��Socket�¼�FD*/
	HANDLE							hEvtHandle;				/*�¼����*/
	ULONG							ulEvtsIndex;				/*�������ڵ�Evts����������*/
	ULONG							ulPeerEvtsIndex;		/*��Ϊ��ǰ��������Ϲ涨�ǳɶԳ��ֵģ����Ա�Ȼ��һ���Զ˵�����*/
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
typedef struct tagSocketMgr
{
	HANDLE				hThreadHandle;								/*�߳̾��*/
	UINT32				uiMgrCtxIndex;								/*���ڹ�������������, ��ԭ�����߳�ʱ����Ҫ*/
	SOCKET				sMsgUdpPort;									/*��ͨ�ŵ�FD, ������Ϣ�˿ھ���,  ֱ����UDPͨ��, ������������Ϣ���̼߳�ͨ��(����ʱ�᲻�ɿ�)*/
	SOCKINFO_S		stArrySockInfo[WSAEVT_NUMS];	/*�����Socket��Ϣ�� ͨ���������������Ϳ��Ժ������¼�������ͬ��������߲���Ч��*/
	SOCK_NEVET_S	stNetEvent;										/*���紥���¼�*/
	ULONG				ulSockNums;									/*��ǰ��û�г���64-4���Ϳ�����, һ������ͨ����, Ȼ�󱣳ֳɶ�*/
}SOCK_MGR_S, *PSOCK_MGR_S;


