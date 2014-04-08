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
 * rex_versus_the_romans.c
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

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <kern/locks.h>

#include "logging.h"
#include "trustedbsd.h"
#include "kauth.h"

#pragma mark TrustedBSD stuff

/* the hooks we want to implement */
static struct mac_policy_ops rex_ops =
{
    .mpo_policy_initbsd = rex_policy_initbsd,       /* some initialization stuff, no access to filesystem here else caboom! */
    .mpo_vnode_check_exec = rex_vnode_check_exec,   /* opportunity to take a peek at what is being executed */
};

static mac_policy_handle_t rex_handle;

static struct mac_policy_conf rex_policy_conf = {
    .mpc_name            = "rex_vs_the_romans",
    .mpc_fullname        = "Rex vs The Romans TrustedBSD module",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &rex_ops,
    /* in DEBUG build we want to be able to load/unload the driver for testing purposes */
#if DEBUG == 1
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK,
#else
    .mpc_loadtime_flags  = 0,
#endif
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

#pragma mark Start and stop functions

kern_return_t rex_versus_the_romans_start(kmod_info_t * ki, void *d);
kern_return_t rex_versus_the_romans_stop(kmod_info_t *ki, void *d);

kern_return_t rex_versus_the_romans_start(kmod_info_t * ki, void *d)
{
    /* kauth takes care of the dropper installing files */
    if ( start_kauth() != KERN_SUCCESS )
    {
        ERROR_MSG("Failed to start kauth!");
        return KERN_FAILURE;
    }
    /* TrustedBSD takes care of detecting already infected machine */
    return mac_policy_register(&rex_policy_conf, &rex_handle, d);
}

kern_return_t rex_versus_the_romans_stop(kmod_info_t *ki, void *d)
{
    stop_kauth();
    return mac_policy_unregister(rex_handle);
}
