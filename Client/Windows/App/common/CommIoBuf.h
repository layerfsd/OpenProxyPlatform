
/*部分可能有特殊的头部*/
#define		IOBUF_MAXSIZE			16384+1024

typedef struct tagCommIoBuf
{
	LIST_ENTRY						stNode;
	UCHAR								acBuf[IOBUF_MAXSIZE];					/*内存大小*/
	UINT32							uiBufSize;											/*投递的内存大小*/
	UINT32							uiDatalen;										/*数据长度*/
}COM_IOBUF_S, *PCOM_IOBUF_S;


COM_IOBUF_S* COMM_IOBUF_Create();

VOID COMM_IOBUF_Free(COM_IOBUF_S* pstIoBuf);

VOID COMM_IOBUF_BufListRelease(PLIST_ENTRY pstList);
