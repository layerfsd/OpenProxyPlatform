#include <Windows.h>
#include <process.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "CLog.h"
#include "CommDef.h"
#include "ComSSLApi.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


#define COMSSL_BUFSIZE	16384 +1024

/*SSL上下文信息*/
typedef struct tagComSSLCtxInfo
{
	SSL_CTX		*pstCtx;
	INT32		iTlsVersion;
	INT32		iCertVerifyEnable;
}COM_SSL_CTX_INFO_S;

/*SSL的句柄，一般单个会话就一个*/
typedef struct tagComSSLInfo
{
	SSL						*pstSsl;
	pfcomssl_recv_handlercb	pfrecvhandlercb;
	SOCKET				sClientSock;
	CHAR					acServerAddr[MAX_PATH];
	INT32					iServerPort;

	CHAR					acPeerCertSubjectName[MAX_PATH];
	CHAR					acPeerCertIssueName[MAX_PATH];
	CHAR					*pcRecvBuf;		/*内存比较大，使用malloc的内存*/

}COM_SSL_INFO_S;

/*本进程的SSL上下文*/
COM_SSL_CTX_INFO_S	*g_pstSslCtxInfo  = NULL;

INT32 COMSSL_API_ClientEnvInit()
{
	WORD wVersionRequested = 0;
	WSADATA wsaData;
	int err;
	COM_SSL_CTX_INFO_S *pstCtxInfo = NULL;

	wVersionRequested = MAKEWORD( 2, 2 );
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"WSAStartup failed with error: %d\n", err);
		return SYS_ERR;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR, "Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return SYS_ERR;
	}
	

	pstCtxInfo = (COM_SSL_CTX_INFO_S *)malloc(sizeof(COM_SSL_CTX_INFO_S));
	if (NULL == pstCtxInfo)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"malloc ssl ctx info error!");
		return SYS_ERR;
	}

	memset(pstCtxInfo, 0, sizeof(COM_SSL_CTX_INFO_S));

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	pstCtxInfo->pstCtx = SSL_CTX_new(TLSv1_client_method());
	if (NULL == pstCtxInfo->pstCtx)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR, "ssl new ctx error (Tlsv1_client_method)!");
		free(pstCtxInfo);
		return SYS_ERR;
	}

	g_pstSslCtxInfo = pstCtxInfo;

	return SYS_OK;
}

VOID COMSSL_API_ClientEnvUnInit()
{
	if (NULL != g_pstSslCtxInfo)
	{
		if (NULL != g_pstSslCtxInfo->pstCtx)
		{
			SSL_CTX_free(g_pstSslCtxInfo->pstCtx);
		}
	}
	WSACleanup();
}

PCOMSSL_HANDLE COMSSL_API_SSLCreate(pfcomssl_recv_handlercb pfRecvHandler)
{
	PCOMSSL_HANDLE pvHandle = NULL;
	COM_SSL_INFO_S *pstSslInfo = NULL;

	if (NULL == pfRecvHandler
		|| NULL == g_pstSslCtxInfo 
		|| NULL == g_pstSslCtxInfo->pstCtx)
	{
		return NULL;
	}

	pstSslInfo = (COM_SSL_INFO_S *)malloc(sizeof(COM_SSL_INFO_S));
	if (NULL == pstSslInfo)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"malloc ssl info error!");
		return NULL;
	}

	memset(pstSslInfo, 0, sizeof(COM_SSL_CTX_INFO_S));

	pstSslInfo->pstSsl = SSL_new(g_pstSslCtxInfo->pstCtx);
	if (NULL == pstSslInfo->pstSsl)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR, "ssl new error!");
		free(pstSslInfo);
		return NULL;
	}

	pstSslInfo->pcRecvBuf = (CHAR *)malloc(COMSSL_BUFSIZE);
	if (NULL == pstSslInfo->pcRecvBuf)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR, "ssl new error!");
		SSL_free(pstSslInfo->pstSsl);
		free(pstSslInfo);
		return NULL;
	}
	pstSslInfo->pfrecvhandlercb = pfRecvHandler;

	pvHandle = (VOID *)pstSslInfo;
	return pvHandle;
}

VOID COMSSL_API_SSLRelease(PCOMSSL_HANDLE pvSslHandle)
{
	COM_SSL_INFO_S *pstSslInfo = NULL;

	if (NULL == pvSslHandle)
	{
		return;
	}

	pstSslInfo = (COM_SSL_INFO_S *)pvSslHandle;
	if (INVALID_SOCKET != pstSslInfo->sClientSock )
	{
		closesocket(pstSslInfo->sClientSock);
		pstSslInfo->sClientSock = INVALID_SOCKET;
	}

	if (NULL != pstSslInfo->pcRecvBuf)
	{
		free(pstSslInfo->pcRecvBuf);
		pstSslInfo->pcRecvBuf = NULL;
	}
	if (NULL != pstSslInfo->pstSsl)
	{
		SSL_free(pstSslInfo->pstSsl);
		pstSslInfo->pstSsl = NULL;
	}
	free(pvSslHandle);
	pvSslHandle = NULL;
}

unsigned int __stdcall	comssl_recv_readhandler(void *argv)
{
	COM_SSL_INFO_S *pstSslHandle = NULL;
	INT32 iRet = 0;
	INT32 iTotalLen = 0;


	if (NULL == argv)
	{
		return -1;
	}

	pstSslHandle = (COM_SSL_INFO_S *)argv;
	
	while (TRUE)
	{
		iRet = COMSSL_API_Read(pstSslHandle, pstSslHandle->pcRecvBuf+ iTotalLen, COMSSL_BUFSIZE);
		iTotalLen += iRet;
		/*出现1个字节的，继续接收*/
		if ( 1 == iTotalLen )
		{
			continue;
		}
		else if ( 0 > iRet || iTotalLen > COMSSL_BUFSIZE)
		{
			CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR, "ssl read error, Notify stop it!", iRet);
			if (NULL != pstSslHandle->pfrecvhandlercb)
			{
				/*iRet = SYS_ERR, 用于传输SSL_read()的错误*/
				pstSslHandle->pfrecvhandlercb(pstSslHandle->pcRecvBuf, iRet);
				memset(pstSslHandle->pcRecvBuf, 0, COMSSL_BUFSIZE);
			}
			return -1;
		}
		else
		{
			/*正常处理*/
			if (NULL != pstSslHandle->pfrecvhandlercb)
			{
				if (SYS_OK == pstSslHandle->pfrecvhandlercb(pstSslHandle->pcRecvBuf, iTotalLen))
				{
					/*清空数据，等待下次接收*/
					memset(pstSslHandle->pcRecvBuf, 0, COMSSL_BUFSIZE);
					iTotalLen = 0;
				}
				else
				{
					/*表示需要继续接收*/
					continue;
				}
			}
		}
	}

	return 0;
}

int COMSSL_API_SSLConnect(PCOMSSL_HANDLE pvSslInfoHandle, char *pcSevAddr, int iSevPort)
{
	INT32		iErr	=	0;
	struct 		sockaddr_in dest_sin;
	X509		*server_cert = NULL;
	char	   	*str = NULL;
	COM_SSL_INFO_S *pstSslInfo = NULL;

	if (NULL == pvSslInfoHandle
		|| NULL == pcSevAddr)
	{
		return SYS_ERR;
	}

	pstSslInfo = (COM_SSL_INFO_S *)pvSslInfoHandle;

	pstSslInfo->sClientSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == pstSslInfo->sClientSock)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl socket create error=%d!", GetLastError());
		return SYS_ERR;
	}

	dest_sin.sin_family = AF_INET;
	dest_sin.sin_addr.s_addr = inet_addr(pcSevAddr);
	dest_sin.sin_port = htons(iSevPort);

	iErr=connect(pstSslInfo->sClientSock,(PSOCKADDR) &dest_sin, sizeof( dest_sin));
	if(iErr<0)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"tcp-connect [%s:%d] error=%d!",pcSevAddr,iSevPort, GetLastError());
		closesocket(pstSslInfo->sClientSock);
		return SYS_ERR;
	}

	if (NULL == pstSslInfo->pstSsl)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl handle is NULL!");
		closesocket(pstSslInfo->sClientSock);
		return SYS_ERR;
	}

	SSL_set_fd(pstSslInfo->pstSsl, (int)pstSslInfo->sClientSock);
	iErr = SSL_connect(pstSslInfo->pstSsl);                     
	if(iErr < 0)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl-connect [%s:%d] error=%d!",pcSevAddr,iSevPort, GetLastError());
		closesocket(pstSslInfo->sClientSock);
		return SYS_ERR;
	}

	server_cert = SSL_get_peer_certificate(pstSslInfo->pstSsl);       
	
	str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
	strcpy_s(pstSslInfo->acPeerCertSubjectName, MAX_PATH-1, str);
	OPENSSL_free (str);
	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
	strcpy_s(pstSslInfo->acPeerCertIssueName, MAX_PATH-1, str);
	OPENSSL_free (str);  	
	X509_free (server_cert);

	//CLOG_writelog_level("COMSSL", CLOG_LEVEL_EVENT,"COMSSL ssl connect [%s:%d] successful!!",pcSevAddr,iSevPort);

	_beginthreadex(NULL,0, comssl_recv_readhandler, pstSslInfo, 0, NULL);

	return 0;
}


int COMSSL_API_Send(PCOMSSL_HANDLE pvSslInfoHandle, char *pcsend, int isendlen)
{
	int iret = 0;
	COM_SSL_INFO_S *pstSslInfo = NULL;

	if (NULL == pvSslInfoHandle
		|| NULL == pcsend)
	{
		return SYS_ERR;
	}

	pstSslInfo = (COM_SSL_INFO_S *)pvSslInfoHandle;

	if (NULL == pstSslInfo->pstSsl)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl send is NULL!");
		return SYS_ERR;
	}

	iret = SSL_write(pstSslInfo->pstSsl, pcsend, isendlen);
	if (iret < 0)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl send error!");
		return SYS_ERR;
	}

	return iret;
}


int COMSSL_API_Read(PCOMSSL_HANDLE pvSslInfoHandle, char *pcbuf, int ibuflen)
{
	int iret = 0;
	COM_SSL_INFO_S *pstSslInfo = NULL;

	if (NULL == pvSslInfoHandle
		|| NULL == pcbuf)
	{
		return SYS_ERR;
	}

	pstSslInfo = (COM_SSL_INFO_S *)pvSslInfoHandle;

	iret = SSL_read(pstSslInfo->pstSsl, pcbuf, ibuflen);
	if (iret < 0)
	{
		CLOG_writelog_level("COMSSL", CLOG_LEVEL_ERROR,"ssl read error!iret=%d", iret);
		return SYS_ERR;
	}

	return iret;
}