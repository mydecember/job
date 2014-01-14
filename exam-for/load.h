
#ifndef __LOAD__H__
#define __LOAD__H__
#include"stdio.h"
#include"stdlib.h"
#include"string.h"
#include"msg/va_list.h"
#include"load_head.h"
#include"ac/acsmx.h"
int init_HB(HB** hb);
void del_HB(HB** hb, SN **free_link);
int init_free_link(SN **free_link, int n);
void del_link(SN* head);
inline SN* get_node(SN** free_link);
void display_link(SN* head);
inline int insert_node(SN** head,SN *node );
inline void resume_node(SN** free_link, SN *p);
inline SN* find_node(SN* head, SSDD *ssdd);
void free_node(SN** free_link, SN** p);
void virtual2real(SN* node,SN**head);
void init_load_table();
int regist_probe(PRO pro_type,LN* ln);
void init_patterns(ACSM_STRUCT ** acsm);
void init_BC(BC** BC_head);
inline BC* get_BC_node(BC** BC_head);
inline void resume_BC_node(BC** BC_head, BC *p);


//extern LN *HTTP_P;
extern int http_num;
//extern LN *FTP_P;
extern int ftp_num;
//extern LN *POP3_P;
extern int pop3_num;
//extern LN *SMTP_P;
extern int smtp_num; 
//extern char ***pro_features;//[][MAX_FEATURE][100];
extern int feature_num[PRO_MAX];
inline void remove_HB_SN(SN** sn, SN* node);

#endif
