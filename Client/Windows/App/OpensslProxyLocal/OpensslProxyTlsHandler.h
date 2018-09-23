#pragma once




VOID		 SSLPROXY_TlsHandler_EnvInit();

UINT32	SSLPROXY_TLSVersionProtoCheck(SOCKET sLocalSock);

SSL_CTX*  SSLPROXY_TLSCtxNewServer();







