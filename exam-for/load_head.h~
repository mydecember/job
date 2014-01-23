
#ifndef __LOAD__HEAD__
#define __LOAD__HEAD__

#define HB_MAX 65536
#define FREE_NODE 50000
#define PRO_PROBE_NUM 20
//pro class
#define MAX_FEATURE 20

#define MAX_BUFFER_FOR_PACKET 3000
#define BC_NUM	700
typedef enum {	
	HTTP=0,
	FTP,
	POP3,
	SMTP,
	UNKOWN,
	PRO_MAX,
	}PRO;

/*typedef struct _loadNode{
	struct _loadNode *next;
	char mac[7];
	int id;
	int loadvalue;
}LN;*/
////////////////buf for packet/////////////////
typedef struct _bufCache{
	unsigned char buf[MAX_BUFFER_FOR_PACKET];
	unsigned char *ptcp;
	int datalen;
	int tcplen;
	struct ip* ip;
	struct _bufCache *next;
}BC;
typedef struct _ssdd{
	unsigned int b_ip;
	unsigned  short  b_port;
	unsigned int l_ip;
	unsigned short l_port;
	
}SSDD;
//tree node
/*
typedef struct _streamNode{
	struct _streamNode *left;
	struct _streamNode *right;
	PRO proto;// protocol id
	int id;//the probe id
}SN;*/
typedef struct _streamNode{
	SSDD sdipport;
	struct _streamNode *next;
	struct _streamNode *pre;
	PRO proto;// protocol id
	int id;//the probe id
	int state;
	BC* bc_head;
	BC* bc_tail;
	int tcp_content_len;
}SN;
typedef struct _hashBase{
	SN * real_sn;
	int real_sn_num;
	SN *virtual_sn;
	int virtual_sn_num;
	int all;	
}HB;


/////////////////////load table///////////////////////
typedef struct _loadNode{
	unsigned char mac[7];
	int probe_id;
	int load_value;
	void *dst_addr;
}LN;
////////////////////////////


//////////////////////////////////////////
#define hash_HB(ipsrc, ipdst)\
((ipsrc)^((ipsrc)>>16)^(ipdst)^((ipdst)>>16))


typedef u_int32_t tcp_seq;
struct fniff_tcp
  {
    u_int16_t th_sport;		/* source port */
    u_int16_t th_dport;		/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;		/* (unused) */
    u_int8_t th_off:4;		/* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;		/* data offset */
    u_int8_t th_x2:4;		/* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* window */
    u_int16_t th_sum;		/* checksum */
    u_int16_t th_urp;		/* urgent pointer */
};

#endif
