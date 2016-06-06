/*******************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2016. All rights reserved.  
* File name: ip.c
* History:   
*     1. Date: 2016/4/26
*         Author: HuXinlei
********************************************************************************
*/

#include "ip.h"
#include "snoopy.h"
#include "securec.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utmp.h>
#include <time.h>
#include <string.h>


#define MAX_SIZE 1024
#define ERR_SIZE 200

/*
 * SNOOPY DATA SOURCE: ip
 *
 * Description:
 *     Returns source ip of current process.
 *
 * Params:
 *     result: pointer to string, to write result into
 *     arg:    (ignored)
 *
 * Return:
 *     number of characters in the returned string, or SNOOPY_DATASOURCE_FAILURE
 */
 
int snoopy_datasource_ip (char * const result, char const * const arg)
{
    int fd;
	int FValue;
	int len = 0;
	
	char ttyname_ip[4097];
	char buff[MAX_SIZE];  
	char *Pos_nextPtr_ip;
	char err[ERR_SIZE] = {0x00};
	FILE *fstream=NULL;    
    size_t  ttynameSize_ip = 4096;
	struct utmp current_utmp;
		char *Pos_nextPtr_ssh;	
	size_t cpylen;
	char temp[MAX_SIZE];
    memset_s(buff,MAX_SIZE,0,sizeof(buff));  

	
	 temp[0] = '\0';
	//get the source ip from variable $SSH_CLIENT
	if(NULL!=(fstream=popen("echo $SSH_CLIENT","r"))) 			
    {   		
       if(NULL!=fgets(buff, sizeof(buff), fstream))   
		{   
			//"buff" includes numbers 
			if((buff[0]>=48) && (buff[0]<=57))  
			{
				Pos_nextPtr_ssh = strstr(buff, " ");    //separate ip address from other value
				cpylen = Pos_nextPtr_ssh - buff;		
				strncpy_s(temp,MAX_SIZE,buff,cpylen);
				temp[cpylen]='\0'; 
				len = snprintf_s(result, SNOOPY_DATASOURCE_MESSAGE_MAX_SIZE, strlen(temp), "%s", temp);		
				pclose(fstream);  
				return len;					
			}
			
		
		}		
		pclose(fstream);  
    }
	
	//if cant't get ip from $SSH_CLIENT, get ip from "who" command
	FValue = ttyname_r(0, ttyname_ip, ttynameSize_ip);
    if (0 == FValue) {
		Pos_nextPtr_ip = strstr(ttyname_ip+1, "/");
		if (-1 == (fd = open(UTMP_FILE, O_RDONLY))) {
			strcpy_s(err, ERR_SIZE, "ERROR(can't open utmp file)");
 			return snprintf_s(result, SNOOPY_DATASOURCE_MESSAGE_MAX_SIZE, strlen(err), "%s", err);
		}
		while (read(fd, &current_utmp, sizeof(current_utmp))) {
			if (USER_PROCESS == current_utmp.ut_type) {
				if (0 == strcmp(current_utmp.ut_line,Pos_nextPtr_ip+1)) {
					if ('\0' != current_utmp.ut_host[0]) {
						len = snprintf_s(result, SNOOPY_DATASOURCE_MESSAGE_MAX_SIZE, strlen(current_utmp.ut_host), "%s", current_utmp.ut_host);
						
						close(fd);
						return len;
					}
				}
			}
		}	
		close(fd);
	}	
	
	
	return snprintf_s(result, SNOOPY_DATASOURCE_MESSAGE_MAX_SIZE, 2, "%s", " ");
	
		
}
