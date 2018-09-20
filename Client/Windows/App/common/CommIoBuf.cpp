#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "CommDef.h"
#include "CommIoBuf.h"
#include "sem.h"
#include "queue.h"


COM_IOBUF_S* COMM_IOBUF_Create()
{
    COM_IOBUF_S*	pstIoBuf = NULL;

	pstIoBuf = (COM_IOBUF_S *)malloc(sizeof(COM_IOBUF_S));
	if (NULL == pstIoBuf)
	{
		return NULL;
	}
	memset(pstIoBuf, 0, sizeof(COM_IOBUF_S));

	InitializeListHead(&pstIoBuf->stNode);
	pstIoBuf->uiBufSize		= IOBUF_MAXSIZE;
	pstIoBuf->uiDatalen		= 0;

	return pstIoBuf;
}

VOID COMM_IOBUF_Free(COM_IOBUF_S* pstIoBuf)
{
	if (NULL != pstIoBuf)
	{
		free(pstIoBuf);
	}
}

VOID COMM_IOBUF_BufListRelease(PLIST_ENTRY pstList)
{
    PCOM_IOBUF_S    pRuleEntry = NULL;
    PLIST_ENTRY		  plistEntry = NULL;

    if (NULL == pstList)
    {
        return;
    }

    while (!IsListEmpty(pstList))
    {
        if (!IsListEmpty(pstList))
        {
            plistEntry = RemoveHeadList(pstList);
        }

        if (plistEntry != NULL)
        {
            pRuleEntry = CONTAINING_RECORD(plistEntry,COM_IOBUF_S,stNode);

            COMM_IOBUF_Free(pRuleEntry);
        }
    }
    return;
}

