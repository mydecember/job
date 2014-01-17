#include"load.h"

//static SN *free_link=NULL;

unsigned char pro_features[PRO_MAX][MAX_FEATURE][100]={
	{{"HTTP/1.1"},{"|"},{"HTTP/1.0"},{""}},//http
	{{"USER"},{"PASS"},{"331"},{""}},//ftp
	{{"+OK"},{"USER"},{"PASS"},{""}},//pop3
	{{"220"},{"EHLO"},{""}},//smtp
	{{""}},//smtp
	};
	static int node_num=FREE_NODE;

int init_HB(HB** hb)
{
	HB *p=(HB*)calloc(HB_MAX,sizeof(HB));
	if(!p)
	{
			msg("EIHB calloc error\n ");
			return -1;
	} 
	else
	{

		int i=0;
		for(i=0;i<HB_MAX;++i)
		{
				p[i].real_sn=NULL;
				p[i].virtual_sn=NULL;
				p[i].real_sn_num=0;
				p[i].virtual_sn_num=0;
		}
		*hb=p;
		return 0;
	}
}
void del_HB(HB** hb, SN **free_link)
{
	int i;
	if(* hb==NULL)
		return ;
	for(i=0;i<HB_MAX;++i)
	{
		del_link((*hb+i)->real_sn);
		del_link((*hb+i)->virtual_sn);
	}
	SN*p=*free_link;
	while(*free_link!=NULL)
	{
		*free_link=(*free_link)->next;
		free(p);
		p=*free_link;
	}
	free(*hb);
	*hb=NULL;
}
void remove_HB_SN(SN** sn, SN* node)
{
	if(node==NULL) return;
	if(*sn==node)
	{
		*sn=(*sn)->next;
		if((*sn)!=NULL)
			(*sn)->pre=NULL;
	}	
	else
	{
		node->pre->next=node->next;
		if(node->next!=NULL)
			node->next->pre=node->pre;
	}
}
int init_free_link(SN **free_link, int n)
{
	SN *p;
	*free_link=NULL;
	while(n--)
	{
		if(*free_link==NULL)
		{
			*free_link=(SN*)calloc(1,sizeof(SN));
			if(*free_link==NULL)
				{
					msg("EIcalloc error\n");
					return -1;
				}
				(*free_link)->next=NULL;
				(*free_link)->pre=NULL;
				(*free_link)->proto=UNKOWN;
				(*free_link)->id=0;
		}
		else
		{
			p=(SN*)calloc(1,sizeof(SN));
			if(p==NULL)
				{
					msg("EIcalloc p error\n");
					return -1;
				}
				p->next=*free_link;
				p->proto=UNKOWN;
				p->id=0;
				p->pre=NULL;
				*free_link=p;	
			
		}
	}
return 1;
}
void del_link(SN* head)
{
	SN*p=head;
	if(p==NULL)
		return;
	while(head)
	{
		p=head;
		head=head->next;
		free(p);
	}
	//free(free_link);
	
}
inline SN* get_node(SN** free_link)
{
	SN* p=*free_link;
	//node_num--;
	//msg("Wnode_num=get:%d\n",node_num);
	if(p==NULL)
	{
		msg("WInode null free_link\n");
		p=(SN*)calloc(1,sizeof(SN));
		if(p==NULL)
			{
				msg("EIcalloc p error\n");
				return NULL;
			}
			p->next=NULL;
			p->proto=UNKOWN;
			p->id=0;
			return p;				
		//return NULL;
	}
	*free_link=(*free_link)->next;
	p->next=NULL;
	return p;
}
void display_link(SN* head)
{
	SN *p=head;
	while(p!=NULL)
	{
		printf("%d ",p->id);
		p=p->next;
	}
	printf("\n");
}
inline int insert_node(SN** head,SN *node )
{
	//int err;
	if(node==NULL)
		{
			msg("EI node point is null\n");
			
			return -1;
		}
		if(*head==NULL)
			{
				//msg("EI head point is null\n");
				*head=node;
				node->next=NULL;
				node->pre=NULL;
			return 0;
			}
	//node->next=*head;
	//*head=node;
	node->next=*head;
	(*head)->pre=node;
//	msg(";;;;;;;\n");
	node->pre=NULL;//(*head)->pre;
//	msg("jjjjjjjjjjjjjj\n");
	*head=node;
	return 0;
	
}
inline void resume_node(SN** free_link, SN *p)
{
	
	//msg("jjjjj;;;jjjjj\n");
	if(p==NULL)
	{msg("EWIeeeeeeeeeee\n");
		//exit(0);
		return;
	}	
	//memset(p,0,sizeof(SN));
	//msg("jjjjjjnnnnjjjj\n");
	
	//msg("jjjjjjbbbbjjjj\n");
	p->pre=NULL;
	//msg("jjjjjj1jjjj\n");
	p->next=*free_link;
	//msg("jjjjjj2jjjj\n");
	*free_link=p;
	//msg("jjjjj6jjjjj\n");
}
inline SN* find_node(SN* head, SSDD *ssdd)
{
//	printf("--------------\n");
	SN*p =head;
	int n=0;
		//msg("WIS ,mmmmmmmmm\n");
	if(p==NULL)
		{
			//msg("WI pointer = NULL\n");
			return NULL;
		}
	//	msg("WIS jjjjjjjj\n");
	while(p!=NULL)
	{
		//msg("kkkkk\n");
		//msg("ddddddddd\n");
		if(p->sdipport.b_ip==ssdd->b_ip&&p->sdipport.b_port==ssdd->b_port&&p->sdipport.l_ip==ssdd->l_ip&&p->sdipport.l_port==ssdd->l_port)
		{
			return p;
			//break;
		}
		
		n++;
		if(n==500)
		{
			msg("too big\n");
			exit(0);
		}
		p=p->next;
	}
	//msg("WIS hhhhhhhhhh\n");
	//msg("not");
	return NULL;
}
/*
int remove_node(SN** head, SSDD *ssdd)
{
	SN *p=*head;
	//SN *q=*head;*/
/*	if(p==NULL||ssdd==NULL)
	{
			msg("WI pointer = NULL\n");
			return 
	};
	while(p)
	{
		if(p->sdipport.b_ip==ssdd->b_ip&&p->sdipport.b_port==ssdd->b_port&&p->sdipport.l_ip==ssdd->l_ip&&p->sdipport.bl_port==ssdd->l_port)
		{
			if(p==q)
			{
				//q->next=NULL;
				*head=NULL;
				
			}
			else
			{
				q->next=p->next;				
			}
			resume_node(q);
			break;
				
		}
		q=p;
		p=p->next;
	}*//*
	p=find_node(*head,ssdd);

	if(p==NULL)
		{
			return -1;
		}
	if(p->pre==NULL)
		{
		
			*head=p->next;
			(*head)->pre=NULL;
			
		}
		else if(p->next==NULL)
		{
		
			p->pre->next=NULL;			
			
		}
		else
		{
	
			p->pre->next=p->next;
			p->next->pre=p->pre;
		
		}
		resume_node(p);
		return 0;	
}*/
void free_node(SN** free_link, SN** p)
{
	if((*p)->pre==NULL)
		{
		
			if((*p)->next!=NULL)
			{
				(*p)=(*p)->next;
			}
			
		}
		else if((*p)->next==NULL)
		{
		
			(*p)->pre->next=NULL;			
			
		}
		else
		{
	
			(*p)->pre->next=(*p)->next;
			(*p)->next->pre=(*p)->pre;
		
		}
		memset((*p),0,sizeof(SN));
	(*p)->next=NULL;
	(*p)->pre=NULL;
	(*p)->next=*free_link;
	*free_link=(*p);
	
		
}
/*
void move_node(SN** head,SN* p)
{
	if(p->pre==NULL&&p->next==NULL)
	{
		
	}	
	 else if(p->pre==NULL&&p->next!=NULL)
		{
		//msg("mm1mm\n");
			*head=p->next;
			(*head)->pre=NULL;
			
			
			
		}
		else if(p->next==NULL&&p->pre!=NULL)
		{
		//msg("mm2mm\n");
			p->pre->next=NULL;			
			
		}
		else
		{
	//msg("mm3mm\n");
			p->pre->next=p->next;
			p->next->pre=p->pre;
		
		}
		memset(p,0,sizeof(SN));
	//msg("mmmm\n");
	//p->next=NULL;
	p->pre=NULL;
	p->next=free_link;
	free_link=p;
	
//node_num++;
	//msg("Wnode_num=%d\n",node_num);
}*/
void virtual2real(SN* node,SN**head)
{
	node->pre->next=node->next;
	node->next->pre=node->pre;
	insert_node(head,node);
}
////////////load node operation///////////////////
/*LN *HTTP_P=NULL;
int http_num=0;
LN *FTP_P=NULL;
int ftp_num=0;
LN *POP3_P=NULL;
int pop3_num=0;
LN *SMTP_P=NULL;
int smtp_num=0; 
*/
//inorder to improve the effective use array instead of link

//LN HTTP_P[PRO_PROBE_NUM]={0};
/*int http_num=0;
//LN FTP_P[PRO_PROBE_NUM]={0};
int ftp_num=0;
//LN POP3_P[PRO_PROBE_NUM]={0};
int pop3_num=0;
//LN *SMTP_P=NULL;
int smtp_num=0; 
int unkown_num=0;*/
int pro_probe_num[PRO_MAX]={0};

LN load_table[PRO_MAX][PRO_PROBE_NUM];
void init_load_table()
{
	int i,j;
	for(i=0;i<PRO_MAX;++i)
	for(j=0;j<PRO_PROBE_NUM;++j)
	{
		memset(load_table[i][j].mac,0,sizeof(load_table[i][j].mac));
		load_table[i][j].probe_id=-1;
		load_table[i][j].load_value=0;
		load_table[i][j].dst_addr=NULL;
	}
}
int regist_probe(PRO pro_type,LN* ln)
{
	int i=0;
	
	for(i=0;i<PRO_PROBE_NUM;++i)
	{
		if(load_table[pro_type][i].probe_id==-1)
		{
			load_table[pro_type][i]=*ln;
			pro_probe_num[pro_type]++;
			break;
		}
	}
	if(i==PRO_PROBE_NUM)
		return -1;
	return 0;
}
 //ACSM_STRUCT *acsm;///////////////ac///////////////////

int feature_num[PRO_MAX]={0};
void init_patterns(ACSM_STRUCT ** acsm)
{
	static flag=0;
	msg("flag=%d\n",flag);
	*acsm=acsmNew();
	int i=0,j=0;
	for(i=0;(i<PRO_MAX)&&(strcmp((char*)pro_features[i][0],""));++i)
	{
		//printf("\ni=%d",i);
		j=0;
		while(strcmp((char*)pro_features[i][j],""))
		{
			if(!strcmp((char*)pro_features[i][j],"|"))
			{
				if(!flag)
				feature_num[i]--;
					j++;
				continue;
			}
			//printf("%s ",pro_features[i][j]);
			acsmAddPattern(*acsm,pro_features[i][j],strlen((char*)pro_features[i][j]),1,i);
			if(!flag)
				feature_num[i]++;
			j++;
		}
	}
	acsmCompile(*acsm);
	flag=1;
	for(i=0;feature_num[i]!=0;++i)
	{
		msg("%d ",feature_num[i]);
	}
	msg("\n");
}

///////////////////////////////

//BC *BC_head=NULL;

////////////buf cache operation/////////////////
void init_BC(BC** BC_head)
{

	BC *p;
	int n=BC_NUM;
	*BC_head=NULL;
	while(n--)
	{
		if(*BC_head==NULL)
		{
			*BC_head=(BC*)calloc(1,sizeof(BC));
			if(*BC_head==NULL)
				{
					msg("EIcalloc error\n");
					return;
				}
				(*BC_head)->next=NULL;
				//free_link->pre=NULL;
				//free_link->proto=UNKOWN;
				//free_link->id=0;
		}
		else
		{
			p=(BC*)calloc(1,sizeof(BC));
			if(p==NULL)
				{
					msg("EIcalloc p error\n");
					return;
				}
				p->next=*BC_head;		
			
				*BC_head=p;	
			
		}
	}
	
}
//static int bc_num=0;
inline BC* get_BC_node(BC** BC_head)
{
	//bc_num++;
	//msg("%d\n",bc_num);
	BC* p=*BC_head;
	
	if(p==NULL)
		{
			//msg("WInode null\n");
			//exit(0);
			p=(BC*)calloc(1,sizeof(BC));
			if(p==NULL)
			{
				msg("EIcalloc p error\n");
				
				return NULL;
			}
			p->next=NULL;
		
			return p;				
			//return NULL;
		}
		*BC_head=(*BC_head)->next;
		p->next=NULL;
		
		return p;
}
inline void resume_BC_node(BC** BC_head, BC *p)
{

	//bc_num--;
	//msg("%d\n",bc_num);
	BC* q=p;
	while(p!=NULL)
	{
		//memset(q,0,sizeof(BC));
		q=p;
		p=p->next;
		q->next=*BC_head;
		*BC_head=q;
	}
	
}
///////////////////////////////////////////////

#ifdef __LOAD_TEST__
void main()
{
}
#endif
