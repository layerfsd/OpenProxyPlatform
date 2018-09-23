

/*�����������͵Ĺ���List*/
typedef enum
{
	OPENSSLPROXY_LISTTYPE_IPPORT = 0,
	OPENSSLPROXY_LISTTYPE_PORT,
	OPENSSLPROXY_LISTTYPE_IPADDR,

	OPENSSLPROXY_LISTTYPE_NUMS,
}RULE_LISTTYPE_E;


/*����˿ڰ�����*/
typedef struct tagRuleWritePortRange
{
	UINT32			uiLocalPortStart;
	UINT32			uiLocalPortEnd;
}RULE_PORTRANGE_S, *PRULE_PORTRANGE_S;

typedef struct tagRuleInfoEntry
{
	LIST_ENTRY		listEntry;
	UINT32			uiRuleType;
	UINT32			uiRuleIP;
	UINT32			uiRulePort;
}RULE_INFO_ENTRY, *PRULE_INFO_ENTRY;

/*�������������*/
typedef struct tagRuleMgrContext
{
	RESOURCE_LOCK_S					stResLock;				/*��Դ��*/
	LIST_ENTRY								stRulePortList;			/*0.0.0.0:8080, �����ַ�Ķ˿�ƥ��*/
	LIST_ENTRY								stRuleIPaddrList;		/*10.10.10.1:0, ����˿ڵĵ�ַƥ��*/
	LIST_ENTRY								stRuleIPPortList;		/*��ȫƥ��*/
	UINT32									uiRuleNums;			/*���й��������*/
	RULE_PORTRANGE_S				stSrcPortRange;		/*Դ�˿ڰ�����*/
}RULE_MGR_CTX_S, *PRULE_MGR_CTX_S;


NTSTATUS	OpenSSLProxy_RuleInit();

VOID			OpenSSLProxy_RuleUnInit();

NTSTATUS	OpenSSLProxy_RuleEntryAdd(IN UINT32 uiRuleIP, IN USHORT usRulePort);

VOID			OpenSSLProxy_RuleEntryRemove(UINT32 uiRuleIP, IN USHORT usRulePort);

VOID			OpenSSLProxy_RuleTypeClear(UINT32 uiRuleType);

VOID			OpenSSLProxy_RuleAllClear();

NTSTATUS	OpenSSLProxy_SetSrcPortRange(UINT32 uiPortStart, UINT32 uiPortEnd);

BOOLEAN	OpenSSLProxy_IsPortInRange(USHORT usSrcPort);

BOOLEAN	OpenSSLProxy_RuleIsMatch(IN UINT32 uiIPAddr, IN USHORT usPort);



