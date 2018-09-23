#ifdef __cplusplus
extern "C" {
#endif

#ifndef _COMSSL_API_H_
#define _COMSSL_API_H_



typedef VOID*	PCOMSSL_HANDLE;

typedef INT32(*pfcomssl_recv_handlercb)(char *pcdata, INT32 datalen);

INT32	COMSSL_API_ClientEnvInit();

VOID	COMSSL_API_ClientEnvUnInit();

PCOMSSL_HANDLE COMSSL_API_SSLCreate(pfcomssl_recv_handlercb pfRecvHandler);

VOID	COMSSL_API_SSLRelease(PCOMSSL_HANDLE pvSslHandle);

int		COMSSL_API_SSLConnect(PCOMSSL_HANDLE pvSslInfoHandle, char *pcSevAddr, int iSevPort);

int		COMSSL_API_Send(PCOMSSL_HANDLE pvSslInfoHandle, char *pcsend, int isendlen);

int		COMSSL_API_Read(PCOMSSL_HANDLE pvSslInfoHandle, char *pcbuf, int ibuflen);

#endif

#ifdef __cplusplus
}
#endif
