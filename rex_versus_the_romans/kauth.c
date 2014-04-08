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
 * kauth.c
 * Created by Pedro Vilaça on 24/03/14.
 *
 * Reference document: Technical Note TN2127 - Kernel Authorization
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

#include "kauth.h"

#include <kern/assert.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/malloc.h>
#include <UserNotification/KUNCUserNotifications.h>

#include "logging.h"

#define PROC_NULL (struct proc *)0

/* local variables */
static kauth_listener_t l_listener = NULL;

/* local functions */
static int fileop_scope_listener(kauth_cred_t credential, void *idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

#pragma mark Start and stop kauth functions

kern_return_t
start_kauth(void)
{
    DEBUG_MSG("Installing kauth hooks...");
    l_listener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, fileop_scope_listener, NULL);
    if (l_listener == NULL)
    {
        ERROR_MSG("Failed to install kauth listener!");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

kern_return_t
stop_kauth(void)
{
    if (l_listener != NULL)
    {
        kauth_unlisten_scope(l_listener);
        l_listener = NULL;
    }
    return KERN_SUCCESS;
}

#pragma mark Our listeners

/* kauth file scope listener 
 * this allows to detect files written to the filesystem
 * arg2 contains a flag KAUTH_FILEOP_CLOSE which is set if a modified file is being closed
 * this way we don't need to trace every close(), only the ones writing to the filesystem
 */
static int
fileop_scope_listener(kauth_cred_t    credential,
                      void *          idata,
                      kauth_action_t  action,
                      uintptr_t       arg0,     /* vnode reference */
                      uintptr_t       arg1,     /* full path to file being closed */
                      uintptr_t       arg2,     /* flags */
                      uintptr_t       arg3)
{
    /* ignore all actions except FILE_CLOSE */
    if (action != KAUTH_FILEOP_CLOSE)
    {
        return KAUTH_RESULT_DEFER;
    }
    
    /* ignore operations with bad data */
    if (credential == NULL || (vnode_t)arg0 == NULL || (char*)arg1 == NULL)
    {
        ERROR_MSG("Arguments contain null pointers!");
        return KAUTH_RESULT_DEFER;
    }
    
    /* ignore closes on folders, character and block devices */
    switch ( vnode_vtype((vnode_t)arg0) )
    {
        case VDIR:
        case VCHR:
        case VBLK:
            return KAUTH_RESULT_DEFER;
        default:
            break;
    }
    
    /* we are only interested when a modified file is being closed */
    if ((int)arg2 != KAUTH_FILEOP_CLOSE_MODIFIED)
    {
        return KAUTH_RESULT_DEFER;
    }
    
    char *file_path = (char*)arg1;
    /* get information from current proc trying to write to the vnode */
    proc_t proc = current_proc();
    pid_t mypid = proc_pid(proc);
    char myprocname[MAXCOMLEN+1] = {0};
    proc_name(mypid, myprocname, sizeof(myprocname));

    /* retrieve the vnode attributes, we can get a lot of vnode information from here */
    struct vnode_attr vap = {0};
    vfs_context_t context = vfs_context_create(NULL);
    /* initialize the structure fields we are interested in
     * reference vn_stat_noauth() xnu/bsd/vfs/vfs_vnops.c
     */
    VATTR_INIT(&vap);
    VATTR_WANTED(&vap, va_mode);
    VATTR_WANTED(&vap, va_type);
    VATTR_WANTED(&vap, va_uid);
    VATTR_WANTED(&vap, va_gid);
    VATTR_WANTED(&vap, va_data_size);
    VATTR_WANTED(&vap, va_flags);
    int attr_ok = 1;
    if ( vnode_getattr((vnode_t)arg0, &vap, context) != 0 )
    {
        /* in case of error permissions and filesize will be bogus */
        ERROR_MSG("failed to vnode_getattr");
        attr_ok = 0;
    }
    /* release the context we created, else kab00m! */
    vfs_context_rele(context);
    
    int error = 0;
    /* make sure we :
     * - were able to read the attributes
     * - file size is at least uint32_t 
     * - path starts with /Users
     */
    if ( attr_ok == 1 &&
         vap.va_data_size >= sizeof(uint32_t) &&
         strprefix(file_path, "/Users/") )
    {
        uint32_t magic = 0;
        /* read target vnode */
        uio_t uio = NULL;
        /* read from offset 0 */
        uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
        if (uio == NULL)
        {
            ERROR_MSG("uio_create returned null!");
            return KAUTH_RESULT_DEFER;
        }
        /* we just want to read 4 bytes to match the header */
        if ( (error = uio_addiov(uio, CAST_USER_ADDR_T(&magic), sizeof(uint32_t))) )
        {
            ERROR_MSG("uio_addiov returned error %d!", error);
            return KAUTH_RESULT_DEFER;
        }
        if ( (error = VNOP_READ((vnode_t)arg0, uio, 0, NULL)) )
        {
            ERROR_MSG("VNOP_READ failed %d!", error);
            return KAUTH_RESULT_DEFER;
        }
        else if (uio_resid(uio))
        {
            ERROR_MSG("uio_resid!");
            return KAUTH_RESULT_DEFER;
        }
        
        /* verify if it's a Mach-O file */
        if (magic == MH_MAGIC || magic == MH_MAGIC_64 || magic == FAT_CIGAM)
        {
            char *token = NULL;
            char *string = NULL;
            char *tofree = NULL;
            int library = 0;
            int preferences = 0;
            
            tofree = string = STRDUP(file_path, M_TEMP);
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
            /* we got a match into /Users/username/Library/Preferences, warn user about it */
            if (library == 1 && preferences == 1)
            {
                DEBUG_MSG("Found Mach-O written to %s by %s.", file_path, myprocname);
                char alert_msg[1025] = {0};
                snprintf(alert_msg, sizeof(alert_msg), "Process \"%s\" wrote Mach-O binary %s.\n This could be Hacking Team's malware!", myprocname, file_path);
                alert_msg[sizeof(alert_msg)-1] = '\0';
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
    }
    /* don't deny access, we are just here to observe */
    return KAUTH_RESULT_DEFER;
}
