/*
 *  ______     ______     __  __
 * /\  == \   /\  ___\   /\_\_\_\
 * \ \  __<   \ \  __\   \/_/\_\/_
 *  \ \_\ \_\  \ \_____\   /\_\/\_\
 *   \/_/ /_/   \/_____/   \/_/\/_/
 *  __   __   ______
 * /\ \ / /  /\  ___\
 * \ \ \'/   \ \___  \
 *  \ \__|    \/\_____\
 *   \/_/      \/_____/
 *  ______   __  __     ______        ______     ______     __    __     ______     __   __     ______
 * /\__  _\ /\ \_\ \   /\  ___\      /\  == \   /\  __ \   /\ "-./  \   /\  __ \   /\ "-.\ \   /\  ___\
 * \/_/\ \/ \ \  __ \  \ \  __\      \ \  __<   \ \ \/\ \  \ \ \-./\ \  \ \  __ \  \ \ \-.  \  \ \___  \
 *    \ \_\  \ \_\ \_\  \ \_____\     \ \_\ \_\  \ \_____\  \ \_\ \ \_\  \ \_\ \_\  \ \_\\"\_\  \/\_____\
 *     \/_/   \/_/\/_/   \/_____/      \/_/ /_/   \/_____/   \/_/  \/_/   \/_/\/_/   \/_/ \/_/   \/_____/
 *
 * Rex versus The Romans
 * Anti Hacking Team Kernel Extension
 *
 * Copyright (c) 2014 Pedro Vilaça. All rights reserved.
 * reverser@put.as - http://reverse.put.as
 *
 * trustedbsd.c
 * Created by Pedro Vilaça on 24/03/14.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "trustedbsd.h"

#include <libkern/libkern.h>
#include <kern/task.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include <UserNotification/KUNCUserNotifications.h>

#include "logging.h"

#define PROC_NULL (struct proc *)0

#pragma mark TrustedBSD hooks implementation

void
rex_policy_initbsd(struct mac_policy_conf *conf)
{
    /* nothing to do here for now ... */
}

/*
 * this hook is called before execution of the binary
 * so we have an opportunity to verify what is being executed
 * always return 0 since we are just observing...
 */
int
rex_vnode_check_exec(kauth_cred_t cred,
                     struct vnode *vp,
                     struct label *label,
                     struct label *execlabel,	/* NULLOK */
                     struct componentname *cnp,
                     u_int *csflags)
{
    proc_t target_proc = current_proc();
    if (target_proc == PROC_NULL)
    {
        ERROR_MSG("Couldn't find process for task!");
        return 0;
    }
    pid_t target_pid = proc_pid(target_proc);

    char path[MAXPATHLEN] = {0};
    int pathbuff_len = sizeof(path);
    if ( vn_getpath(vp, path, &pathbuff_len) != 0 )
    {
        ERROR_MSG("Can't build path to vnode!");
        return 0;
    }
    /* path will not be NULL here afterwards */
    
    /* check if we are executing from /Users, ignore everything else */
    if ( strprefix(path, "/Users/") )
    {
        char *token = NULL;
        char *string = NULL;
        char *tofree = NULL;
        int library = 0;
        int preferences = 0;
        
        tofree = string = STRDUP(path, M_TEMP);
        while ((token = strsep(&string, "/")) != NULL)
        {
            if (strcmp(token, "Library") == 0)
            {
                library = 1;
            }
            else if (library == 1 && strcmp(token, "Preferences") == 0)
            {
                preferences = 1;
            }
        }
        _FREE(tofree, M_TEMP);
        if (library == 1 && preferences == 1)
        {
            DEBUG_MSG("Hacking Team are dorks because they are executing %s from ~/Library/Preferences.", path);
            char alert_msg[1025] = {0};
            snprintf(alert_msg, sizeof(alert_msg), "Process \"%s\" with PID %d is executing from ~/Library/Preferences.\n This could be Hacking Team's malware!", path, target_pid);
            alert_msg[sizeof(alert_msg)-1] = '\0';

            /* log to syslog */
            printf("[WARNING] Process \"%s\" with PID %d is executing from ~/Library/Preferences.\n This could be Hacking Team's malware!", path, target_pid);
            /* deprecated but still usable to display the alert */
            KUNCUserNotificationDisplayNotice(10,		// Timeout
                                              0,		// Flags - default is Stop alert level
                                              NULL,     // iconpath
                                              NULL,     // soundpath
                                              NULL,     // localization path
                                              "Security Alert", // alert header
                                              alert_msg, // alert message
                                              "OK");	// button title
        }
    }
    /* just watching... */
    return 0;
}
