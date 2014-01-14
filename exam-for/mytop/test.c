#include"stdio.h"
 int get_sys_info(float *sysinfo,int n);
int main()
{
	float f[10]={0.0};
	int i;
	int j;
get_sys_info(f,10);
usleep(600000);
for(j=0;j<10;++j){
	get_sys_info(f,10);
	
	for(i=0;i<10;++i)
	printf("%.1f\t",f[i]);
	printf("\n--------------\n");
	sleep(1);
}
	return 0;
}
