#include <Winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <process.h>

#include "../common/CLog.h"
#include "../common/CommDef.h"
#include "../common/CommBizDefine.h"
#include "../common/Sem.h"
#include "../common/Queue.h"
#include "../common/CommIoBuf.h"
#include "OpensslProxyTlsHandler.h"


/*判断SSL的缓存大小*/
#define		SSLCHECK_BUFSIZE		16

#define		SERVERCERTFILE		".\\cacert.pem"
#define		SERVERKEYFILE			".\\privkey.pem"

VOID SSLPROXY_TlsHandler_EnvInit()
{
	SSL_library_init();
	OPENSSL_malloc_init();
	SSLeay_add_ssl_algorithms();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
}


SSL_CTX *SSLPROXY_TLSCtxNewServer()
{
	SSL_CTX * pstTlsCtxServer = NULL;

	pstTlsCtxServer = SSL_CTX_new(SSLv23_server_method());
	if (NULL == pstTlsCtxServer)
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL Ctx server create error!");
		return NULL;
	}

	if (SSL_CTX_use_certificate_file(pstTlsCtxServer, SERVERCERTFILE, SSL_FILETYPE_PEM) <= 0) {
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL set server certificate file error!");
		SSL_CTX_free(pstTlsCtxServer);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(pstTlsCtxServer, SERVERKEYFILE, SSL_FILETYPE_PEM) <= 0) {
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL set server key pem file error!");
		SSL_CTX_free(pstTlsCtxServer);
		return NULL;
	}

	if ( !SSL_CTX_check_private_key(pstTlsCtxServer) )
	{
		CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "SSL Ctx server create error!");
		SSL_CTX_free(pstTlsCtxServer);
		return NULL;
	}

	return pstTlsCtxServer;
}


UINT32	SSLPROXY_TLSVersionProtoCheck(SOCKET sLocalSock)
{
	INT32		iRet = 0;
	CHAR		acBuf[SSLCHECK_BUFSIZE] = { 0 };
	UINT32	uiTlsVersion = TLSVERSION_NOTSSL;

	if ( INVALID_SOCKET == sLocalSock)
	{
		return uiTlsVersion;
	}

	for (int i = 0; i < 5; i++)
	{
		iRet = recv(sLocalSock, acBuf, 8, MSG_PEEK);
		if (iRet > 0)
		{
			if (acBuf[0] == 0x16 /* SSLv3/TLSv1 */)
			{
				if ( acBuf[1] == 0x03 && acBuf[2] == 0x00  )
				{
					/*TLSV1.0*/
					uiTlsVersion = TLSVERSION_1_0;
				}

				if (acBuf[1] == 0x03 && acBuf[2] == 0x01)
				{
					/*TLSV1.0*/
					uiTlsVersion = TLSVERSION_1_1;
				}
				if (acBuf[1] == 0x03 && acBuf[2] == 0x02)
				{
					/*TLSV1.0*/
					uiTlsVersion = TLSVERSION_1_2;
				}
				if (acBuf[1] == 0x03 && acBuf[2] == 0x03)
				{
					/*TLSV1.0*/
					uiTlsVersion = TLSVERSION_1_3;
				}
			}

#if 0
			/*不支持SSL2.0版本，基本没人用了*/
			else if ((acBuf[0] & 0x80) /* SSLv2 */)
			{
				bRet = TRUE;
			}
#endif

			return uiTlsVersion;
		}
		else if (0 == iRet)
		{
			CLOG_writelog_level("LPXY", CLOG_LEVEL_EVENT, "Ssl recv peek check continue, iRet=%d, error=%d!\n", iRet, GetLastError());
			Sleep(100);
			continue;
		}
		else
		{
			CLOG_writelog_level("LPXY", CLOG_LEVEL_ERROR, "Ssl recv peek check error, iRet=%d, error=%d!\n", iRet, GetLastError());
		}
	}
	return uiTlsVersion;
}



