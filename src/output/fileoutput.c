/*
 * SNOOPY LOGGER
 *
 * File: snoopy/output/fileoutput.c
 *
 * Copyright (c) 2015 Bostjan Skufca (bostjan _A_T_ a2o.si)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
/********************************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2016. All rights reserved.  
* File name: fileoutput.h
* History:   
*     1. Date: 2016/4/26
*         Author: HuXinlei
*		  Modification: employ Inter-Process Communication (IPC) techniques, 
*            in order to not grant the specialed log directory and files write pemission to 
*			non-root users any more.
*********************************************************************************************
*/

 

#include "fileoutput.h"
#include "snoopy.h"
#include "configuration.h"
#include "securec.h" 
#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <unistd.h>


#define MAX_TEXT 4096
struct msg_st
{
	long int msg_type;
	char text[MAX_TEXT];
};


/*
 * SNOOPY OUTPUT: fileoutput (called like this because <socket.h> is system library
 *
 * Description:
 *     Sends given message to message queue
 *
 * Params:
 *     logMessage: message to send
 *     errOrMsg:   is message and error message or ordinary Snoopy log message
 *     arg:        output argument(s)
 *
 * Return:
 *     int:        See snoopy.h (SNOOPY_OUTPUT_*) for details.
 */
int snoopy_output_fileoutput (char const * const logMessage, int errorOrMessage, char const * const arg)
{
 
	int msgid = -1;
	
	struct msg_st data;
	
	char name[MAX_TEXT];
	char *tmp = "&&";
	char *enter = "\n\r";
	
	
	//create message queue
	msgid = msgget((key_t)1234, 0666 | IPC_CREAT);
	if(msgid == -1)
	{
		return SNOOPY_OUTPUT_FAILURE;
	}
	
	//input data
	data.msg_type = 1;    
	strcat_s(name,MAX_TEXT,arg);
	strcat_s(name,MAX_TEXT,tmp);
	strcat_s(name,MAX_TEXT,logMessage);
	strcat_s(name,MAX_TEXT,enter);
	strcpy_s(data.text, MAX_TEXT, name);
	//send message to queue
	if(msgsnd(msgid, (void*)&data, MAX_TEXT, IPC_NOWAIT) == -1)
	{
		return SNOOPY_OUTPUT_FAILURE;
	}
		
	memset_s(data.text,MAX_TEXT,0,strlen(data.text));
	memset_s(name,MAX_TEXT,0,strlen(name));
	return strlen(logMessage);
}
