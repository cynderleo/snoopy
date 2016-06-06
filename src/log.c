/*
 * SNOOPY LOGGER
 *
 * File: log.c
 *
 * Copyright (c) 2014-2015 Bostjan Skufca <bostjan@a2o.si>
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

/*******************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2016. All rights reserved.  
* File name: log.c
* History:   
*     1. Date: 2016/4/26
*         Author: HuXinlei
*		  Modification: default logging commands associated with process sshd,xientd,login
********************************************************************************
*/ 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * Includes order: from local to global
 */
#include "log.h"
#include "snoopy.h"
#include "configuration.h"
#if defined(SNOOPY_FILTERING_ENABLED)
#include "filtering.h"
#endif
#include "inputdatastorage.h"
#include "message.h"
#include "misc.h"
#include "outputregistry.h"
#include "securec.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>

/*
 * snoopy_log_syscall_execv
 *
 * Description:
 *     Log the call to syscall execv()
 *
 * Params:
 *     filename:   filename of program being executed
 *     argv:       arguments being passed to execv()
 *
 * Return:
 *     void
 */
void snoopy_log_syscall_execv (
    const char *filename,
    char *const argv[]
) {
    // Syscall was done without new environmental variables, so let's create
    // a fake empty array to simulate it.
    char *envp[] = { NULL };

    snoopy_log_syscall_exec("execv", filename, argv, envp);
}



/*
 * snoopy_log_syscall_execve
 *
 * Description:
 *     Log the call to syscall execve()
 *
 * Params:
 *     filename:   filename of program being executed
 *     argv:       arguments being passed to execve()
 *     envp:       environment being passed to execve()
 *
 * Return:
 *     void
 */
void snoopy_log_syscall_execve (
    const char *filename,
    char *const argv[],
    char *const envp[]
) {
    snoopy_log_syscall_exec("execve", filename, argv, envp);
}



/*
 * snoopy_log_syscall_exec
 *
 * Description:
 *     Common routine that does execv(e)() logging
 *
 * Params:
 *     syscallName:   system call name to log
 *     filename:      filename of program being executed
 *     argv:          arguments being passed to execv(e)()
 *     envp:          environment being passed to execve()
 *
 * Return:
 *     void
 */
void snoopy_log_syscall_exec (
    const char *syscallName,
    const char *filename,
    char *const argv[],
    char *const envp[]
) {
	char *rproname_Tag;
	char *exclude_rpro;
	int FValue = -1;
    char *logMessage = NULL;
    snoopy_configuration_t *CFG;


    /* Initialize Snoopy */
    snoopy_init();

    /* Get config pointer */
    CFG = snoopy_configuration_get();

    // Store arguments passed to execv(e)()
    snoopy_inputdatastorage_store_filename(filename);
    snoopy_inputdatastorage_store_argv((char**)argv);
    snoopy_inputdatastorage_store_envp((char**)envp);

    /* Initialize empty log message */
    logMessage    = malloc(SNOOPY_LOG_MESSAGE_MAX_SIZE);
    logMessage[0] = '\0';

    /* Generate log message in specified format */
    snoopy_message_generateFromFormat(logMessage, CFG->message_format);

#if defined(SNOOPY_FILTERING_ENABLED)
    /* Should message be passed to syslog or not? */
    if (
        (SNOOPY_FALSE == CFG->filtering_enabled)
        ||
        (
            (SNOOPY_TRUE == CFG->filtering_enabled)
            &&
            (SNOOPY_FILTER_PASS == snoopy_filtering_check_chain(logMessage, CFG->filter_chain))
        )
    ) {
#endif
		rproname_Tag = strstr(CFG->filter_chain, "only_rproname");
		exclude_rpro = strstr(CFG->filter_chain, "exclude_spawns_of");
		if ((NULL == rproname_Tag) && (NULL == exclude_rpro))
		{		
		//if there is no only_rproname and exclude_spawns_of, only log commands of sshd, xinetd and login process
			FValue = osaudit_rproname_sx();
			if (FValue == SNOOPY_FILTER_PASS) {		

				snoopy_log_dispatch(logMessage, SNOOPY_LOG_MESSAGE);

			}
		
		}
		else
		{
			snoopy_log_dispatch(logMessage, SNOOPY_LOG_MESSAGE);
			
		}
      
#if defined(SNOOPY_FILTERING_ENABLED)
    }
#endif

    /* Housekeeping */
    free(logMessage);
    snoopy_cleanup();
}

int osaudit_rproname_sx ()
{
    return get_rproname_sx(getpid());
}



// Read /proc/{pid}/status file and extract the property
char* read_proc_property_sx (int pid, char* prop_name)
{
    char    pid_file[50];
    FILE   *fp;
    char   *line = NULL;
    size_t  lineLen = 0;
    char   *find_name;
    char   *find_name_value;
    size_t  value_size = 0;
    char    returnValue[NAME_MAX+1] = "";

  
    sprintf_s(pid_file, 50, "/proc/%d/status", pid);
    fp = fopen(pid_file, "r");
    if (NULL == fp) {
        return NULL;
    }

    
    while (getline(&line, &lineLen, fp) != -1) {

        if (0 == lineLen) {
			goto End_and_Clean;
			
        }

        if (NULL == strstr(line, ":")) {
 			goto End_and_Clean;
        }

        
        char *savePtr = "";
        find_name = strtok_r(line, ":", &savePtr);
        find_name_value = strtok_r(NULL, ":", &savePtr);
        if (NULL == find_name_value) {
            continue;
        }

        
        if (strcmp(prop_name, find_name) == 0) {
            find_name_value++;                  // There is one tab in front of PID number
            value_size = strlen(find_name_value); 
            find_name_value[value_size-1] = 0;       // Terminate the newline at the end of value
            value_size--;                       // Length is now shorter for 1 character

           
            if (value_size > NAME_MAX) {
                strncpy_s(returnValue, NAME_MAX+1, find_name_value, NAME_MAX);
                returnValue[NAME_MAX] = 0; 
            } else {
                strncpy_s(returnValue, NAME_MAX+1, find_name_value, NAME_MAX+1);
            }

          
            free(line);
            fclose(fp);
            return strdup(returnValue);
        } 
    }

End_and_Clean:
		if (NULL != line) {
				free(line);
			}
			fclose(fp);
			return NULL;	
	
}


//find root process name
int get_rproname_sx (int pid)
{
    int     RootPid;
    char   *name;
	char   *ppid_str;
	int FValuesx = -1;
    ppid_str = read_proc_property_sx(pid, "PPid");
    if (NULL != ppid_str) {
        RootPid = atoi(ppid_str);  
    }
	else
		RootPid = 0;

    if (1 == RootPid) {
        name = read_proc_property_sx(pid, "Name");
        if ((strcmp(name,"sshd") == 0) || (strcmp(name,"xinetd") == 0)|| (strcmp(name,"login") == 0)) {
            FValuesx = SNOOPY_FILTER_PASS;
        } 
        return FValuesx;
    } else if (0 == RootPid) {
		FValuesx = SNOOPY_FILTER_DROP;
        return FValuesx;
    } else {
        return get_rproname_sx(RootPid);
    }
}

/*
 * snoopy_log_dispatch
 *
 * Description:
 *     Dispatch given message to configured output
 *
 * Params:
 *     logMessage:       message to dispatch
 *     errorOrMessage:   is this a message or an error?
 *
 * Return:
 *     int:              See snoopy.h (SNOOPY_OUTPUT_*) for details.
 */
int snoopy_log_dispatch (
    char *logMessage,
    int   errorOrMessage
) {
    /* Dispatch only if non-zero size */
    if (0 == strlen(logMessage)) {
        return SNOOPY_OUTPUT_GRACEFUL_DISCARD;
    }

    // Dispatch to configured output
    return snoopy_outputregistry_dispatch(logMessage, errorOrMessage);
}
