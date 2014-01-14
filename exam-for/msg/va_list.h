#ifndef __VA_LIST__
#define __VA_LIST__

//open or close flag
//#define __MSG__DEBUG__

int vpf(  char *fmt,const char *function,const char *file,int line, ...);
#ifdef __MSG__DEBUG__
#define msg(fmt,...)\
	do{\
	vpf(fmt,__FILE__,__FUNCTION__,__LINE__,##__VA_ARGS__);\
	}while(0)
#else
#define msg(...) do{}while(0)
#endif 

#endif
