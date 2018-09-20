#ifndef _COMM_DEF_H_
#define _COMM_DEF_H_


/******************************************************************************/
/*��������ֵ*/
#ifndef SYS_OK
#define SYS_OK				0
#endif

#ifndef SYS_ERR
#define SYS_ERR				0xFFFFFFFF//~(0)
#endif

#ifndef SYS_TRUE
#define SYS_TRUE			1
#endif

#ifndef SYS_FALSE
#define SYS_FALSE			0
#endif

#ifndef SYS_INVALUE
#define SYS_INVALUE		0xFFFFFFFF	
#endif

/******************************************************************************/
#define     MGR_ERRCODE_SUCCESS          0
#define     MGR_ERRCODE_PARAM            -1
#define     MGR_ERRCODE_TIMEOUT         -2

/******************************************************************************/
/*�����߳�����WSAEventSelect����,  һ��������һ������ͨ�ŵ�UDP*/
#define		WSAEVT_NUMS		        MAXIMUM_WAIT_OBJECTS	
/*��ǰȫ�ֵ���ഴ�����̸߳���*/
#define		MGR_ARRYNUMS           128

/*����64λ��GUID��Ψһ���ӱ�ʶ��, ͳһ���ݱ�ʶ����й���*/
#define		MGR_GUIDLEN                 64

/*�Զ�������ջ��С*/
#define		MGR_STACKSIZE               256*1024

/*�����Ķ���*/
#define		MGR_LISTENUMS               50

/*�����ַ���*/
#define		MGR_LOCALADDRA          "127.0.0.1"
/*��ַ����*/
#define		MGR_IPV4LEN                     32
/*Ĭ�ϵı��ؼ����˿�*/
#define		MGR_LISTENPORT              9890


/***************************�������������*******************************************/
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                        (PCHAR)(address) - \
                                        (ULONG_PTR)(&((type *)0)->field)))

FORCEINLINE VOID InitializeListHead(
	_Out_ PLIST_ENTRY ListHead
)
{
	ListHead->Flink = ListHead->Blink = ListHead;
	return;
}

BOOLEAN CFORCEINLINE IsListEmpty(
    _In_ const LIST_ENTRY * ListHead
)
{

    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE BOOLEAN RemoveEntryList(
	_In_ PLIST_ENTRY Entry
)
{
	PLIST_ENTRY PrevEntry;
	PLIST_ENTRY NextEntry;

	NextEntry = Entry->Flink;
	PrevEntry = Entry->Blink;

	PrevEntry->Flink = NextEntry;
	NextEntry->Blink = PrevEntry;
	return (BOOLEAN)(PrevEntry == NextEntry);
}

FORCEINLINE PLIST_ENTRY RemoveHeadList(
	_Inout_ PLIST_ENTRY ListHead
)
{
	PLIST_ENTRY Entry;
	PLIST_ENTRY NextEntry;

	Entry = ListHead->Flink;
	NextEntry = Entry->Flink;

	ListHead->Flink = NextEntry;
	NextEntry->Blink = ListHead;

	return Entry;
}

FORCEINLINE PLIST_ENTRY RemoveTailList(
	_Inout_ PLIST_ENTRY ListHead
)
{
	PLIST_ENTRY Entry;
	PLIST_ENTRY PrevEntry;

	Entry = ListHead->Blink;
	PrevEntry = Entry->Blink;

	ListHead->Blink = PrevEntry;
	PrevEntry->Flink = ListHead;
	return Entry;
}


FORCEINLINE VOID InsertTailList(
	_Inout_ PLIST_ENTRY ListHead,
	_Out_ __drv_aliasesMem PLIST_ENTRY Entry
)
{
	PLIST_ENTRY PrevEntry;

	PrevEntry = ListHead->Blink;

	Entry->Flink = ListHead;
	Entry->Blink = PrevEntry;
	PrevEntry->Flink = Entry;
	ListHead->Blink = Entry;
	return;
}


FORCEINLINE VOID InsertHeadList(
	_Inout_ PLIST_ENTRY ListHead,
	_Out_ __drv_aliasesMem PLIST_ENTRY Entry
)
{
	PLIST_ENTRY NextEntry;

	NextEntry = ListHead->Flink;
	Entry->Flink = NextEntry;
	Entry->Blink = ListHead;
	NextEntry->Blink = Entry;
	ListHead->Flink = Entry;
	return;
}

#endif