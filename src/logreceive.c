#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/msg.h>
#include "securec.h"

struct msg_st
{
	long int msg_type;
	char text[BUFSIZ];
};

int main()
{
	int running = 1;
	int msgid = -1;	
	while(running)
	{
		struct msg_st data;
		long int msgtype = 0;
		char tmpstr[2048];
		char filename[1024];
		size_t  num;
		char *filepos; 
		FILE *fp;
		//建立消息队列
		msgid = msgget((key_t)1234, 0666 | IPC_CREAT);
		if(msgid == -1)
		{
			exit(EXIT_FAILURE);
		}
		if(msgrcv(msgid, (void*)&data, BUFSIZ, msgtype, 0) == -1)
		{
			exit(EXIT_FAILURE);
		}
		
		strcpy_s(tmpstr,2048,data.text);

		filepos=strstr(tmpstr,"&&");
		if (filepos == NULL)
		{
			fp = fopen("/root/log","a");
			if (fp != NULL)
			{	
				fprintf(fp,"%s",data.text);
			}			
			fclose(fp);
		}
		else
		{
			num=filepos-tmpstr;
			strncpy_s(filename,1024,tmpstr,num);
			filename[num]='\0';
			fp = fopen(filename,"a");
			if (fp != NULL)
			{	
				fprintf(fp,"%s",filepos+2);
			}		
			fclose(fp);
		}
		
		memset_s(data.text,BUFSIZ,0,sizeof(data.text));  
		memset_s(tmpstr,2048,0,sizeof(tmpstr));  
		memset_s(filename,1024,0,sizeof(filename));  
	}
	//删除消息队列
	if(msgctl(msgid, IPC_RMID, 0) == -1)
	{
		fprintf(stderr, "msgctl(IPC_RMID) failed\n");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}