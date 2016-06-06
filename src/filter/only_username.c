/*******************************************************************************
* Copyright @ Huawei Technologies Co., Ltd. 1998-2016. All rights reserved.  
* File name: only_username.c
* History:   
*     1. Date: 2016/4/26
*         Author: HuXinlei		
********************************************************************************
*/

#include "only_username.h"
#include "snoopy.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

/*
 * SNOOPY FILTER: only_username
 *
 * Description:
 *     Logs only commands associated with a username
 *
 * Params:
 *     msg: Pointer to string that contains formatted log message (may be manipulated)
 *     arg:        Comma-separated list of program names for the username of which log messages are passed.
 *
 * Return:
 *     SNOOPY_FILTER_PASS or SNOOPY_FILTER_DROP
 */

int snoopy_filter_only_username (char *msg, char const * const arg)
{
    char  *username_list    = NULL;
    char **list_parse = NULL;
    int    username_num  = 0;
    int    FValue    = -1;

	struct passwd  pwd;
    struct passwd *pwd_uid = NULL;
    char          *passwd_buf = NULL;
    long           passwd_size = 0;
	
   
    passwd_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (-1 == passwd_size) {
        passwd_size = 16384;
    }
    passwd_buf = malloc(passwd_size);
    if (NULL == passwd_buf) {
        goto END_FREE;
    }

    if (0 != getpwuid_r(getuid(), &pwd, passwd_buf, passwd_size, &pwd_uid)) {
        goto END_FREE;
    } else {
        if (NULL == pwd_uid) {
            goto END_FREE;
        } 
    }

    username_list   = strdup(arg);
    username_num = snoopy_parser_argList_csv(username_list, &list_parse);

    //find username
    for (int i=0 ; i<username_num ; i++) {
 		//log commands if success
        if (strcmp(pwd_uid->pw_name,list_parse[i])==0) {
            FValue = SNOOPY_FILTER_PASS;
            goto END_FREE;
        }
    }
    FValue = SNOOPY_FILTER_DROP;
	goto END_FREE;
	
END_FREE:	
    free(username_list);
	free(list_parse);
	free(passwd_buf);
	return FValue;

}




