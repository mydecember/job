

#ifndef _DELTATIME
#define _DELTATIME
//#define __TEST__

#include"stdio.h"
#include"time.h"

#define NS_TIME(time) struct timespec spec_##time={0,0},now_##time={0,0}
#define NS_TIME_START(time) ({clock_gettime(CLOCK_REALTIME,&(spec_##time));})
#define NS_TIME_END(time) ({clock_gettime(CLOCK_REALTIME,&now_##time);\
	delta_time(&now_##time,&spec_##time);})

#define get_time(time) spec_##time

long delta_time (struct timespec * now,
                 struct timespec * before);

#endif
