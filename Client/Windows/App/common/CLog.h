
#ifdef __cplusplus
extern "C" {
#endif


#define CLOG_LEVEL_ERROR	1		/*���󼶱���־: ��Ҫ���Error: */
#define CLOG_LEVEL_WARNING	2		/*�澯������־: ��Ҫ���Warning:*/
#define CLOG_LEVEL_EVENT	3		/*������ӡ��־*/
#define CLOG_LEVEL_DEBUG	4		/*������־*/

#define CLOG_LEVEL_STR_ERROR		"Error  :"	/*������־ǰ�����ERROR*/
#define CLOG_LEVEL_STR_WARING	"Warning:"
#define CLOG_LEVEL_STR_LEN		8			/*�ַ����룬ǰ�涼����8������*/

/*��־Ŀ¼����*/
#define CLOG_DIRNAME	"OpenSSLProxy\\log"	

/*��־���ȵ���*/
#define CLOG_BUFLEN		1024

#ifndef SYS_ERR
#define SYS_ERR -1
#endif

#ifndef SYS_OK
#define SYS_OK 0
#endif

#ifndef SYS_CONTUE
#define SYS_CONTUE		-2
#endif

/*��־�ļ�����*/
typedef enum
{
	CLOG_TYPE_DEVCTRL = 0,	/**/

	CLOG_TYPE_NUMS
}CLOG_TYPE_E;

int		CLOG_evn_init(CLOG_TYPE_E eType);

void		CLOG_evn_uninit();

void		CLOG_writelog(char *pcModuleName, const char *fmt, ...);

void		CLOG_writelog_level(char *pcModuleName, int level, const char *fmt, ...);


#ifdef __cplusplus
}
#endif
