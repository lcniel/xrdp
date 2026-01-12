/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Copyright (C) Jay Sorg 2004-2025
 *
 * BSD process grouping by:
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland.
 * Copyright (c) 2000-2001 Markus Friedl.
 * Copyright (c) 2011-2015 Koichiro Iwao, Kyushu Institute of Technology.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 * @file session.c
 * @brief Session management definitions
 *
 * This module wraps the session management classes
 * @author Matt Burt
 *
 */

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include <stdio.h>

#include "session.h"
#include "session_base.h"
#include "session_parameters.h"

#include "sesman_auth.h"
#include "sesman_config.h"
#include "env.h"
#include "log.h"
#include "login_info.h"
#include "os_calls.h"
#include "sesexec.h"
#include "trans.h"
#include "xrdp_sockets.h"

struct session_data
{
    pid_t x_server; ///< PID of X server
    pid_t win_mgr; ///< PID of window manager
    pid_t chansrv; ///< PID of chansrv
    time_t start_time;
    unsigned int connect_count;
    struct session_parameters params;
    // Flexible array member used to store strings in params and ip_addr;
#ifdef __cplusplus
    char strings[1];
#else
    char strings[];
#endif
};

/******************************************************************************/
/**
 * Starts a session from an operating system perspective
 * @param login_info login info for user
 * @param s session_parameters
 * @return Status
 */
static struct session_data *
session_data_new(const struct session_parameters *sp)
{
    unsigned int string_length = 0;
    // What string length do we need?
    string_length += g_strlen(sp->shell) + 1;
    string_length += g_strlen(sp->directory) + 1;

    struct session_data *sd = (struct session_data *)g_malloc(sizeof(*sd) + string_length, 0);

    if (sd == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Out of memory allocating session data struct");
    }
    else
    {
        sd->win_mgr = -1;
        sd->x_server = -1;
        sd->chansrv = -1;
        sd->start_time = 0;
        sd->connect_count = 0;

        /* Copy all the non-string session parameters... */
        sd->params = *sp;

        /* ...and then the strings */
        char *memptr = sd->strings;

#define COPY_STRING(dest,src) \
    (dest) = memptr; \
    strcpy(memptr, src); \
    memptr += strlen(memptr) + 1

        COPY_STRING(sd->params.shell, sp->shell);
        COPY_STRING(sd->params.directory, sp->directory);

#undef COPY_STRING
    }

    return sd;
}

/******************************************************************************/
void
session_data_free(struct session_data *session_data)
{
    if (session_data != NULL)
    {
#ifdef USE_DEVEL_LOGGING
        if (session_data->win_mgr > 0)
        {
            LOG_DEVEL(LOG_LEVEL_WARNING,
                      "Freeing session data with valid window manager PID %d",
                      session_data->win_mgr);
        }
        if (session_data->x_server > 0)
        {
            LOG_DEVEL(LOG_LEVEL_WARNING,
                      "Freeing session data with valid X server PID %d",
                      session_data->x_server);
        }
        if (session_data->chansrv > 0)
        {
            LOG_DEVEL(LOG_LEVEL_WARNING,
                      "Freeing session data with valid chansrv PID %d",
                      session_data->chansrv);
        }
#endif

        free(session_data);
    }
}

/******************************************************************************/
/**
 * Creates a string consisting of all parameters that is hosted in the param list
 * @param outstr allocate this buffer before you use this function
 * @param len the allocated len for outstr
 */
static char *
dumpItemsToString(struct list *self, char *outstr, int len)
{
    int index;
    int totalLen = 0;

    g_memset(outstr, 0, len);
    if (self->count == 0)
    {
        LOG_DEVEL(LOG_LEVEL_TRACE, "List is empty");
    }

    for (index = 0; index < self->count; index++)
    {
        /* +1 = one space*/
        totalLen = totalLen + g_strlen((char *)list_get_item(self, index)) + 1;

        if (len > totalLen)
        {
            g_strcat(outstr, (char *)list_get_item(self, index));
            g_strcat(outstr, " ");
        }
    }

    return outstr ;
}

/******************************************************************************/
static void
start_chansrv(const struct login_info *login_info,
              const struct session_parameters *s,
              void *closure /* unused */)
{
    struct list *chansrv_params = list_create();
    const char *exe_path = XRDP_SBIN_PATH "/xrdp-chansrv";

    if (chansrv_params != NULL)
    {
        chansrv_params->auto_free = 1;
        if (!list_add_strdup(chansrv_params, exe_path))
        {
            list_delete(chansrv_params);
            chansrv_params = NULL;
        }
    }

    if (chansrv_params == NULL)
    {
        LOG(LOG_LEVEL_ERROR, "Out of memory starting chansrv");
    }
    else
    {
        env_set_user(login_info->uid, 0, s->display,
                     g_cfg->env_names,
                     g_cfg->env_values);

        LOG_DEVEL_LEAKING_FDS("chansrv", 3, -1);

        /* executing chansrv */
        g_execvp_list(exe_path, chansrv_params);

        /* should not get here */
        list_delete(chansrv_params);
    }
}

/******************************************************************************/
static void
start_window_manager(const struct login_info *login_info,
                     const struct session_parameters *s,
                     void *closure /* unused */)
{
    char text[256];

    env_set_user(login_info->uid,
                 0,
                 s->display,
                 g_cfg->env_names,
                 g_cfg->env_values);

    auth_set_env(login_info->auth_info);
    LOG_DEVEL_LEAKING_FDS("window manager", 3, -1);

    if (s->directory[0] != '\0')
    {
        if (g_cfg->sec.allow_alternate_shell)
        {
            g_set_current_dir(s->directory);
        }
        else
        {
            LOG(LOG_LEVEL_WARNING,
                "Directory change to %s requested, but not "
                "allowed by AllowAlternateShell config value.",
                s->directory);
        }
    }

    if (g_cfg->sec.allow_alternate_shell &&
            g_cfg->sec.pass_shell_as_env != NULL &&
            g_cfg->sec.pass_shell_as_env[0] != '0')
    {
        // Pass the shell in to the standard startwm scripts
        // in an environment variable
        LOG(LOG_LEVEL_INFO,
            "Setting variable '%s' to the specified shell of '%s'",
            g_cfg->sec.pass_shell_as_env,
            s->shell);
        g_setenv_log(g_cfg->sec.pass_shell_as_env, s->shell, 1);
    }
    else if (s->shell[0] != '\0')
    {
        // Try to execute the shell directly (if permitted)
        if (g_cfg->sec.allow_alternate_shell)
        {
            if (g_strchr(s->shell, ' ') != 0 || g_strchr(s->shell, '\t') != 0)
            {
                LOG(LOG_LEVEL_INFO,
                    "Using user requested window manager on "
                    "display %u with embedded arguments using a shell: %s",
                    s->display, s->shell);
                const char *argv[] = {"sh", "-c", s->shell, NULL};
                g_execvp("/bin/sh", (char **)argv);
            }
            else
            {
                LOG(LOG_LEVEL_INFO,
                    "Using user requested window manager on "
                    "display %d: %s", s->display, s->shell);
                g_execlp3(s->shell, s->shell, 0);
            }
        }
        else
        {
            LOG(LOG_LEVEL_WARNING,
                "Shell %s requested by user, but not allowed by "
                "AllowAlternateShell config value.",
                s->shell);
        }
    }
    else
    {
        LOG(LOG_LEVEL_DEBUG, "The user session on display %u did "
            "not request a specific window manager", s->display);
    }

    /* try to execute user window manager if enabled */
    if (g_cfg->enable_user_wm)
    {
        g_snprintf(text, sizeof(text), "%s/%s",
                   g_getenv("HOME"), g_cfg->user_wm);
        if (g_file_exist(text))
        {
            LOG(LOG_LEVEL_INFO,
                "Using window manager on display %u"
                " from user home directory: %s", s->display, text);
            g_execlp3(text, g_cfg->user_wm, 0);
        }
        else
        {
            LOG(LOG_LEVEL_DEBUG,
                "The user home directory window manager configuration "
                "is enabled but window manager program does not exist: %s",
                text);
        }
    }

    LOG(LOG_LEVEL_INFO,
        "Using the default window manager on display %u: %s",
        s->display, g_cfg->default_wm);
    g_execlp3(g_cfg->default_wm, g_cfg->default_wm, 0);

    /* still a problem starting window manager just start xterm */
    LOG(LOG_LEVEL_WARNING,
        "No window manager on display %u started, "
        "so falling back to starting xterm for user debugging",
        s->display);
    g_execlp3("xterm", "xterm", 0);

    /* should not get here */
    LOG(LOG_LEVEL_ERROR, "A fatal error has occurred attempting to start "
        "the window manager on display %u, aborting connection",
        s->display);
}

/******************************************************************************/
static struct list *
prepare_xorg_xserver_params(const struct session_parameters *s,
                            const char *authfile)
{

    char screen[32]; /* display number */
    char text[128];
    const char *xserver;

    struct list *params = list_create();
    if (params != NULL)
    {
        params->auto_free = 1;

        /*
         * Make sure Xorg doesn't run setuid root. Root access is not
         * needed. Xorg can fail when run as root and the user has no
         * console permissions.
         */
        if (g_cfg->sec.xorg_no_new_privileges && g_no_new_privs() != 0)
        {
            LOG(LOG_LEVEL_WARNING,
                "[session start] (display %u): Failed to disable "
                "setuid on X server: %s",
                s->display, g_get_strerror());
        }

        g_snprintf(screen, sizeof(screen), ":%u", s->display);

        /* some args are passed via env vars */
        g_snprintf(text, sizeof(text), "%d", s->width);
        g_setenv_log("XRDP_START_WIDTH", text, 1);

        g_snprintf(text, sizeof(text), "%d", s->height);
        g_setenv_log("XRDP_START_HEIGHT", text, 1);

        g_snprintf(text, sizeof(text), "%d", g_cfg->sess.max_idle_time);
        g_setenv_log("XRDP_SESMAN_MAX_IDLE_TIME", text, 1);

        g_snprintf(text, sizeof(text), "%d", g_cfg->sess.max_disc_time);
        g_setenv_log("XRDP_SESMAN_MAX_DISC_TIME", text, 1);

        g_snprintf(text, sizeof(text), "%d", g_cfg->sess.kill_disconnected);
        g_setenv_log("XRDP_SESMAN_KILL_DISCONNECTED", text, 1);

        /* get path of Xorg from config */
        xserver = (const char *)list_get_item(g_cfg->xorg_params, 0);

        /* these are the must have parameters */
        list_add_strdup_multi(params,
                              xserver, screen,
                              "-auth", authfile,
                              NULL);

        /* additional parameters from sesman.ini file */
        list_append_list_strdup(g_cfg->xorg_params, params, 1);
    }

    return params;
}

/******************************************************************************/
/**
 * Prepare a list of parameters for the Xvnc X server
 * @param s Session parameters
 * @param authfile XAUTHORITY file
 * @param passwd_file VNC password file, or NULL
 * @param port UDS port to connect to, or NULL
 * @return parameters list
 *
 * One of passwd_file and port must be set
 */
static struct list *
prepare_xvnc_xserver_params(const struct session_parameters *s,
                            const char *authfile,
                            const char *passwd_file,
                            const char *port)
{
    char screen[32] = {0}; /* display number */
    char geometry[32] = {0};
    char depth[32] = {0};
    char guid_str[GUID_STR_SIZE];
    const char *xserver;

    struct list *params = list_create();
    if (params != NULL)
    {
        params->auto_free = 1;

        g_snprintf(screen, sizeof(screen), ":%u", s->display);
        g_snprintf(geometry, sizeof(geometry), "%dx%d", s->width, s->height);
        g_snprintf(depth, sizeof(depth), "%d", s->bpp);

        guid_to_str(&s->guid, guid_str);
        env_check_password_file(passwd_file, guid_str);

        /* get path of Xvnc from config */
        xserver = (const char *)list_get_item(g_cfg->vnc_params, 0);

        /* these are the must have parameters */
        list_add_strdup_multi(params,
                              xserver, screen,
                              "-auth", authfile,
                              "-geometry", geometry,
                              "-depth", depth,
                              NULL);

        if (passwd_file != NULL)
        {
            /* RFB authorization */
            list_add_strdup_multi(params,
                                  "-rfbauth", passwd_file,
                                  NULL);
        }
        else if (port != NULL)
        {
            /* UDS connection. Authorization is handled by standard socket
             * permissions, so we do not need to authorize within the
             * VNC protocol exchange as well */
            char sock_mode[16];

            /* Convert a standard permissions mask into decimal
             * for the -rfbunixmode switch argument
             */
            g_snprintf(sock_mode, sizeof(sock_mode),
                       "%d", 0660); /* rw-rw---- */

            list_add_strdup_multi(params,
                                  "-rfbunixpath", port,
                                  "-rfbunixmode", sock_mode,
                                  "-SecurityTypes", "None",
                                  NULL);
        }

        /* additional parameters from sesman.ini file */
        //config_read_xserver_params(SCP_SESSION_TYPE_XVNC,
        //                           xserver_params);
        list_append_list_strdup(g_cfg->vnc_params, params, 1);
    }
    return params;
}

/******************************************************************************/
/* Either execs the X server, or returns */
static void
start_x_server(const struct login_info *login_info,
               const struct session_parameters *s,
               void *closure /* unused */)
{
    char authfile[256]; /* The filename for storing xauth information */
    char execvpparams[2048];
    char *passwd_file = NULL;
    struct list *xserver_params = NULL;
    int unknown_session_type = 0;

    if (s->type == SCP_SESSION_TYPE_XVNC)
    {
        env_set_user(login_info->uid,
                     &passwd_file,
                     s->display,
                     g_cfg->env_names,
                     g_cfg->env_values);
    }
    else
    {
        env_set_user(login_info->uid,
                     0,
                     s->display,
                     g_cfg->env_names,
                     g_cfg->env_values);
    }

    /* prepare the Xauthority stuff */
    if (g_getenv("XAUTHORITY") != NULL)
    {
        g_snprintf(authfile, sizeof(authfile), "%s",
                   g_getenv("XAUTHORITY"));
    }
    else
    {
        g_snprintf(authfile, sizeof(authfile), "%s", ".Xauthority");
    }

    /* Add the entry in XAUTHORITY file or exit if error */
    if (add_xauth_cookie(s->display, authfile) != 0)
    {
        LOG(LOG_LEVEL_ERROR,
            "Error setting the xauth cookie for display %u in file %s",
            s->display, authfile);
    }
    else
    {
        switch (s->type)
        {
                char port[256];

            case SCP_SESSION_TYPE_XORG:
                xserver_params = prepare_xorg_xserver_params(s, authfile);
                break;

            case SCP_SESSION_TYPE_XVNC:
                xserver_params = prepare_xvnc_xserver_params(s, authfile,
                                 passwd_file, NULL);
                break;

            case SCP_SESSION_TYPE_XVNC_UDS:
                g_snprintf(port, sizeof(port), XRDP_X11RDP_STR,
                           login_info->uid, s->display);
                xserver_params = prepare_xvnc_xserver_params(s, authfile,
                                 NULL, port);
                break;

            default:
                unknown_session_type = 1;
        }

        if (xserver_params == NULL)
        {
            LOG(LOG_LEVEL_ERROR, "Out of memory allocating X server params");
        }
        else if (unknown_session_type)
        {
            LOG(LOG_LEVEL_ERROR, "Unknown session type: %d",
                s->type);
        }
        else
        {
            /* fire up X server */
            LOG(LOG_LEVEL_INFO, "Starting X server on display %u: %s",
                s->display,
                dumpItemsToString(xserver_params, execvpparams, 2048));
            LOG_DEVEL_LEAKING_FDS("X server", 3, -1);
            g_execvp_list((const char *)xserver_params->items[0],
                          xserver_params);
        }
    }

    /* should not get here */
    g_free(passwd_file);
    list_delete(xserver_params);
    LOG(LOG_LEVEL_ERROR, "A fatal error has occurred attempting "
        "to start the X server on display %u, aborting connection",
        s->display);
}

/******************************************************************************/
/*
 * Simple helper process to fork a child and log errors */
static int
fork_child(
    void (*runproc)(const struct login_info *,
                    const struct session_parameters *,
                    void *closure),
    const struct login_info *login_info,
    const struct session_parameters *s,
    pid_t group_pid,
    void *closure)
{
    int pid = g_fork();
    if (pid == 0)
    {
        /* Child process */
        if (group_pid >= 0)
        {
            (void)g_setpgid(0, group_pid);
        }
        runproc(login_info, s, closure);
        g_exit(0);
    }

    if (pid < 0)
    {
        LOG(LOG_LEVEL_ERROR, "Fork failed [%s]", g_get_strerror());
    }

    return pid;
}

/******************************************************************************/
static int
process_startup_wait_time(struct session_data *sd)
{
    int rv = 0;
    int robjs_count;
    intptr_t robjs[10];
    unsigned int start = g_get_elapsed_ms();

    LOG(LOG_LEVEL_INFO, "Waiting for %u ms for session to start",
        g_cfg->sess.startup_wait_time);
    while (1)
    {
        unsigned int elapsed = g_get_elapsed_ms() - start;
        if (elapsed >= g_cfg->sess.startup_wait_time)
        {
            break;
        }

        robjs_count = 0;
        robjs[robjs_count++] = g_term_event;
        robjs[robjs_count++] = g_sigchld_event;

        if (g_obj_wait(robjs, robjs_count, NULL, 0,
                       g_cfg->sess.startup_wait_time - elapsed) != 0)
        {
            /* should not get here */
            LOG(LOG_LEVEL_WARNING, "process_startup_wait_time: "
                "Unexpected error from g_obj_wait()");
            g_sleep(100);
            continue;
        }

        if (g_is_wait_obj_set(g_term_event)) /* term */
        {
            // Simulate success for now, but leave g_term_event set. The
            // main loop will also pick up the terminate event and the
            // session will be closed normally
            break;
        }

        if (g_is_wait_obj_set(g_sigchld_event)) /* SIGCHLD */
        {
            g_reset_wait_obj(g_sigchld_event);
            session_process_sigchld_event(sd);
            if (sd->win_mgr < 0)
            {
                // Session has failed in the StartupWaitTime
                // Wait for the rest of the session to finish
                rv = 1;
                session_send_term(sd, 1);
                break;
            }
        }
    }

    return rv;
}

/******************************************************************************/
static enum scp_screate_status
session_start_preamble(struct login_info *login_info,
                       const struct session_parameters *s)
{
    /* Set the secondary groups before starting the session to prevent
     * problems on PAM-based systems (see Linux pam_setcred(3)).
     * If we have *BSD setusercontext() this is not done here */
#ifndef HAVE_SETUSERCONTEXT
    if (g_initgroups(login_info->username) != 0)
    {
        LOG(LOG_LEVEL_ERROR,
            "Failed to initialise secondary groups for %s: %s",
            login_info->username, g_get_strerror());
        return E_SCP_SCREATE_GENERAL_ERROR;
    }
#endif

    if (auth_start_session(login_info->auth_info, s->x11_display) != 0)
    {
        // Errors are logged by the auth module, as they are
        // specific to that module
        return E_SCP_SCREATE_GENERAL_ERROR;
    }
#ifdef USE_BSD_SETLOGIN
    /**
     * Create a new session and process group since the 4.4BSD
     * setlogin() affects the entire process group
     */
    if (g_setsid() < 0)
    {
        LOG(LOG_LEVEL_WARNING,
            "[session start] (display %d): setsid failed - pid %d",
            s->x11_display, g_getpid());
    }

    if (g_setlogin(login_info->username) < 0)
    {
        LOG(LOG_LEVEL_WARNING,
            "[session start] (display %d): setlogin failed for user %s - pid %d",
            s->x11_display, login_info->username, g_getpid());
    }
#endif

    return E_SCP_SCREATE_OK;
}

/******************************************************************************/
enum scp_screate_status
session_start(struct login_info *login_info,
              const struct session_parameters *sp,
              struct session_data **session_data)
{
    enum scp_screate_status status = E_SCP_SCREATE_GENERAL_ERROR;
    /* Create the session_data struct first */
    struct session_data *self = session_base_new(sp);
    if (self == NULL)
    {
        status = E_SCP_SCREATE_NO_MEMORY;
    }
    else
    {
        status = session_start_preamble(login_info, sp);
        if (status == E_SCP_SCREATE_OK)
        {
            status = self->vtable->start(self, login_info, sp);
            if (status == E_SCP_SCREATE_OK)
            {
                *session_data = self;
            }
            else
            {
                *session_data = NULL;
                session_data_free(self);
            }
        }
    }

    return status;
}

/******************************************************************************/
void
session_data_free(struct session_data *self)
{
    session_base_destroy(self);
}

/******************************************************************************/
void
session_process_sigchld_event(struct session_data *self)
{
    // The base class does this, as the base class method needs to be called
    // from other base class methods.
    session_base_process_sigchld_event(self);
}

/******************************************************************************/
unsigned int
session_active(const struct session_data *self)
{
    return self->vtable->active_processes(self);
}

/******************************************************************************/
time_t
session_get_start_time(const struct session_data *self)
{
    return self->start_time;
}

/******************************************************************************/
const char *
session_get_display(const struct session_data *self)
{
    return self->display;
}

/******************************************************************************/
unsigned int
session_increment_connect_count(struct session_data *self)
{
    return self->connect_count++;
}

/******************************************************************************/
static void
start_reconnect_script(struct session_data *self,
                       const struct login_info *login_info,
                       void *closure)
{
    env_set_user(login_info->uid, 0,
                 g_cfg->env_names,
                 g_cfg->env_values);

    auth_set_env(login_info->auth_info);

    if (g_file_exist(g_cfg->reconnect_sh))
    {
        /* The 'closure' parameter points to a list of strings
         * which need to be set in the environment for the reconnect script */
        if (closure != NULL)
        {
            const char **p = (const char **)closure;
            while (*p != NULL && *(p + 1) != NULL)
            {
                (void)g_setenv(*p, *(p + 1), 1);
                p += 2;
            }
        }
        LOG_DEVEL_LEAKING_FDS("reconnect script", 3, -1);

        LOG(LOG_LEVEL_INFO,
            "Starting session reconnection script on display %s: %s",
            self->display, g_cfg->reconnect_sh);
        g_execlp3(g_cfg->reconnect_sh, g_cfg->reconnect_sh, 0);

        /* should not get here */
        LOG(LOG_LEVEL_ERROR,
            "Error starting session reconnection script on display %s: %s",
            self->display, g_cfg->reconnect_sh);
    }
    else
    {
        LOG(LOG_LEVEL_WARNING,
            "Session reconnection script file does not exist: %s",
            g_cfg->reconnect_sh);
    }
}

/******************************************************************************/
void
session_run_reconnect_script(struct session_data *self,
                             const struct login_info *login_info,
                             const char *vars[])
{
    if (session_base_fork_child(self,
                                login_info,
                                self->vtable->getpgid(self),
                                start_reconnect_script,
                                (void *)vars) < 0)
    {
        LOG(LOG_LEVEL_ERROR, "Failed to fork for session reconnection script");
    }
}

/******************************************************************************/
const struct session_parameters *
session_get_parameters(const struct session_data *self)
{
    return self->params;
}

/******************************************************************************/
void
session_send_term(struct session_data *self, int wait_for_all)
{
    // The base class does this, as the base class method needs to be called
    // from other base class methods.
    session_base_send_term(self, wait_for_all);
}

/******************************************************************************/
int
session_get_display_server_fd(const struct session_data *self,
                              const struct login_info *login_info)
{
    return self->vtable->get_display_server_fd(self, login_info);
}

/******************************************************************************/
int
session_get_chansrv_fd(const struct session_data *self,
                       const struct login_info *login_info)
{
    char portname[XRDP_SOCKETS_MAXPATH];

    int rv = -1;

    if (self->chansrv_pid <= 0)
    {
        LOG(LOG_LEVEL_ERROR,
            "Request to connect to chansrv on display %s"
            " which has exited", self->display);
    }
    else
    {
        g_snprintf(portname, sizeof(portname), XRDP_CHANSRV_STR,
                   login_info->uid, STRIP_COLON(self->display));

        // Use the transport library to get the fd
        struct trans *t = trans_create(TRANS_MODE_UNIX, 8192, 8192);
        if (t == NULL)
        {
            LOG(LOG_LEVEL_ERROR, "Out of memory creating transport");
        }
        else if (trans_connect(t, NULL, portname, 10 * 1000) != 0)
        {
            LOG(LOG_LEVEL_ERROR, "Can't connect to chansrv on %s [%s]",
                self->display,
                g_get_strerror());
        }
        else
        {
            rv = t->sck;
            t->sck = -1;
        }
        trans_delete(t);
    }

    return rv;
}
