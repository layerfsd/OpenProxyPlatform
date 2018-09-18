#pragma once


/*负载均衡算法*/
typedef enum
{
	PROXY_BLANCEALGM_LEASTCONN = 0,

	PROXY_BLANCEALGM_NUMS
}PROXY_BLANALGM_E;


/*新来的本地的socket信息*/
typedef struct tagLocalSockInfo
{
	SOCKET			    sLocalFD;					/*本地的Socket信息*/
	SOCKADDR_IN	stLocalInfo;				/*本地的Socket信息*/
}CLIENT_INFO_S, *PCLIENT_INFO_S;

/*分派转发包处理: TODO: 可以做一些过滤的操作*/
typedef struct tagDispatchPackContext
{
	HANDLE				    hThreadHandle;		/*线程等待句柄*/
	HANDLE				    hCompleteEvent;		/*完成事件*/
	PCLIENT_INFO_S	    pstClientInfo;			/*新的客户端连接信息*/
	ULONG				    ulBlanceAlgm;			/*分发的均衡算法*/
}DISPATCHPACK_CTX_S, *PDISPATCHPACK_CTX_S;


DISPATCHPACK_CTX_S *OpensslProxy_DispatchPackCtxCreate();

VOID OpensslProxy_DispatchPackCtxRelease(PDISPATCHPACK_CTX_S pstDispatchCtx);





