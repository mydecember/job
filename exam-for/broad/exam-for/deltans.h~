

#ifndef _DELTATIME
#define _DELTATIME
//#define __TEST__

#include"stdio.h"
#include"time.h"

#define NS_TIME(time) struct timespec spec_##time={0,0},now_##time={0,0},my_end_##time={0,0}
#define NS_TIME_START(time) ({clock_gettime(CLOCK_REALTIME,&(spec_##time));})
#define NS_TIME_END(time) ({clock_gettime(CLOCK_REALTIME,&now_##time);\
	my_end_##time=delta_time(&now_##time,&spec_##time);})
#define NS_GET_TIMEP(time) (&my_end_##time)

#define get_time(time) spec_##time

#define DELAY_INI() struct timespec _delay_time1 , _delay_time2;long m_sec,m_delay=0,m_temp
#define DELAY(n) ({clock_gettime(CLOCK_REALTIME,&_delay_time1);\
	do{\
	clock_gettime(CLOCK_REALTIME,&_delay_time2);\
	m_delay=m_temp=_delay_time2.tv_nsec-_delay_time1.tv_nsec;\
	if(m_temp<0){\
	m_delay=1000000000+m_temp;\
	}\
	}while(m_delay<n);\
	})
	
	

struct timespec delta_time (struct timespec * now,
                 struct timespec * before);
void speed(struct timespec *p, int n,int len);

#endif
