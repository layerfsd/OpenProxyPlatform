
/*���ֿ����������ͷ��*/
#define		IOBUF_MAXSIZE			16384+1024

typedef struct tagCommIoBuf
{
	LIST_ENTRY						stNode;
	UCHAR								acBuf[IOBUF_MAXSIZE];					/*�ڴ��С*/
	UINT32							uiBufSize;											/*Ͷ�ݵ��ڴ��С*/
	UINT32							uiDatalen;										/*���ݳ���*/
}COM_IOBUF_S, *PCOM_IOBUF_S;


COM_IOBUF_S* COMM_IOBUF_Create();

VOID COMM_IOBUF_Free(COM_IOBUF_S* pstIoBuf);

VOID COMM_IOBUF_BufListRelease(PLIST_ENTRY pstList);
