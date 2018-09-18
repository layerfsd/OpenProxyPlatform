#ifndef  _DRVCTRLAPI_H_
#define _DRVCTRLAPI_H_

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN		OpenSSLProxy_DrvCtrl_EnvLibInit();

VOID				OpenSSLProxy_DrvCtrl_EnvLibUnInit();

BOOLEAN		OpenSSLProxy_DrvCtrl_RuleMatchEnable();

BOOLEAN		OpenSSLProxy_DrvCtrl_RuleMatchDisable();

BOOLEAN		OpenSSLProxy_DrvCtrl_SetLocalProxyInfo(UINT32 uiPID, UINT32 uiTcpPort);

BOOLEAN       OpenSSLProxy_DrvCtrl_SetRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort);
BOOLEAN       OpenSSLProxy_DrvCtrl_DelRuleIPAddr(UINT32 uiIPAddr, UINT32 uiIPPort);
BOOLEAN       OpenSSLProxy_DrvCtrl_ClearRuleIPAddr();
BOOLEAN       OpenSSLProxy_DrvCtrl_ClearRuleIPAddrWithType(UINT32 uiType);

BOOLEAN       OpenSSLProxy_DrvCtrl_SetLocalPortRange(UINT32 uiLocalStart, UINT32 uiLocalEnd);
UINT32           OpenSSLProxy_DrvCtrl_GetLocalPortRange(CHAR *pcBuf, INT32 uiBufLen);

#ifdef __cplusplus
}
#endif

#endif
