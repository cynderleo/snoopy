/*******************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2016. All rights reserved.  
* File name: only_rproname.c
* History:   
*     1. Date: 2016/4/26
*         Author: HuXinlei	
*	      modification: some function reference to rpname.c
********************************************************************************
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "only_rproname.h"
#include "snoopy.h"
#include "parser.h"
#include "securec.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>



int get_rproname_only (int pid, char **list_parse_only, int uid_num_only);
char* read_proc_property_only (int pid, char* prop_name);

/*
 * SNOOPY FILTER: only_rproname
 *
 * Description:
 *     Logs only commands associated with a root process name.
 *
 * Params:
 *     msg: Pointer to string that contains formatted log message (may be manipulated)
 *     arg:        Comma-separated list of program names for the spawns of which log messages are passed.
 *
 * Return:
 *     SNOOPY_FILTER_PASS or SNOOPY_FILTER_DROP
 */
 
int snoopy_filter_only_rproname (char *msg, char const * const arg)
{
    char  *uid_list    = NULL;
    char **list_parse = NULL;
    int    uid_num  = 0;
    int    FValue    = -1;

   
    uid_list   = strdup(arg);
    uid_num = snoopy_parser_argList_csv(uid_list, &list_parse);
	
	for (int i=0 ; i<uid_num ; i++) {
		//if parameter include "all", don't filter any root process
		if (strcmp("all", list_parse[i]) == 0) {
			FValue = SNOOPY_FILTER_PASS;
			return FValue;				
			}
	}
	
	
	FValue = get_rproname_only(getpid(), list_parse, uid_num);
	
	free(uid_list);
    free(list_parse);
    return FValue;
	
}


// Read /proc/{pid}/status file and extract the property
char* read_proc_property_only (int pid, char* prop_name)
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
            find_name_value[value_size-1] = 0;        // Terminate the newline at the end of value
            value_size--;              			 // Length is now shorter for 1 character

           
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
int get_rproname_only (int pid, char **list_parse_only, int uid_num_only)
{
    int     RootPid;
    char   *name;
	char   *ppid_str;
	int FValue = -1;
    ppid_str = read_proc_property_only(pid, "PPid");
    if (NULL != ppid_str) {
        RootPid = atoi(ppid_str);
        free(ppid_str);    
    }
	else
		RootPid = 0;

    if (1 == RootPid) {
        name = read_proc_property_only(pid, "Name");
        if (NULL != name) {
			FValue = SNOOPY_FILTER_DROP;
            for (int i=0 ; i<uid_num_only ; i++) {			
				if (strcmp(name, list_parse_only[i]) == 0) {
					FValue = SNOOPY_FILTER_PASS;
					
				}
			} 
		}        
		return FValue;
    } else if (0 == RootPid) {
		FValue = SNOOPY_FILTER_DROP;
        return FValue;
    } else {
        return get_rproname_only(RootPid, list_parse_only, uid_num_only);
    }
}
