/*
 * Copyright © 2013 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Author: Hans de Goede <hdegoede@redhat.com>
 */

#ifdef HAVE_XORG_CONFIG_H
#include <xorg-config.h>
#endif

#include <dbus/dbus.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "os.h"
#include "globals.h"
#include "dbus-core.h"
#include "xf86.h"
#include "xf86platformBus.h"
#include "xf86Xinput.h"
#include "xf86Priv.h"

#include "systemd-logind.h"
#include <systemd/sd-login.h>

#define DBUS_TIMEOUT 500 /* Wait max 0.5 seconds */

struct systemd_logind_info {
    DBusConnection *conn;
    char *session_id;
    char *session_object_path;
    sd_login_monitor *login_monitor;
    Bool active;
    Bool vt_active;
};

static struct systemd_logind_info logind_info;
static Bool hook_added;

static void systemd_logind_release_control(struct systemd_logind_info *info);

static InputInfoPtr
systemd_logind_find_info_ptr_by_devnum(InputInfoPtr start,
                                       int major, int minor)
{
    InputInfoPtr pInfo;

    for (pInfo = start; pInfo; pInfo = pInfo->next)
        if (pInfo->major == major && pInfo->minor == minor &&
                (pInfo->flags & XI86_SERVER_FD))
            return pInfo;

    return NULL;
}

static void
systemd_logind_set_input_fd_for_all_devs(int major, int minor, int fd,
                                         Bool enable)
{
    InputInfoPtr pInfo;

    pInfo = systemd_logind_find_info_ptr_by_devnum(xf86InputDevs, major, minor);
    while (pInfo) {
        pInfo->fd = fd;
        pInfo->options = xf86ReplaceIntOption(pInfo->options, "fd", fd);
        if (enable)
            xf86EnableInputDeviceForVTSwitch(pInfo);

        pInfo = systemd_logind_find_info_ptr_by_devnum(pInfo->next, major, minor);
    }
}

int
systemd_logind_take_fd(int _major, int _minor, const char *path,
                       Bool *paused_ret)
{
    struct systemd_logind_info *info = &logind_info;
    InputInfoPtr pInfo;
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    dbus_int32_t major = _major;
    dbus_int32_t minor = _minor;
    dbus_bool_t paused;
    int fd = -1;

    if (!info->session_object_path || major == 0)
        return -1;

    /* logind does not support mouse devs (with evdev we don't need them) */
    if (strstr(path, "mouse"))
        return -1;

    /* Check if we already have an InputInfo entry with this major, minor
     * (shared device-nodes happen ie with Wacom tablets). */
    pInfo = systemd_logind_find_info_ptr_by_devnum(xf86InputDevs, major, minor);
    if (pInfo) {
        LogMessage(X_INFO, "systemd-logind: returning pre-existing fd for %s %u:%u\n",
               path, major, minor);
        *paused_ret = FALSE;
        return pInfo->fd;
    }

    dbus_error_init(&error);

    msg = dbus_message_new_method_call("org.freedesktop.login1", info->session_object_path,
            "org.freedesktop.login1.Session", "TakeDevice");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    if (!dbus_message_append_args(msg, DBUS_TYPE_UINT32, &major,
                                       DBUS_TYPE_UINT32, &minor,
                                       DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply) {
        LogMessage(X_ERROR, "systemd-logind: failed to take device %s: %s\n",
                   path, error.message);
        goto cleanup;
    }

    if (!dbus_message_get_args(reply, &error,
                               DBUS_TYPE_UNIX_FD, &fd,
                               DBUS_TYPE_BOOLEAN, &paused,
                               DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: TakeDevice %s: %s\n",
                   path, error.message);
        goto cleanup;
    }

    *paused_ret = paused;

    LogMessage(X_INFO, "systemd-logind: got fd for %s %u:%u fd %d paused %d\n",
               path, major, minor, fd, paused);

cleanup:
    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);

    return fd;
}

void
systemd_logind_release_fd(int _major, int _minor, int fd)
{
    struct systemd_logind_info *info = &logind_info;
    InputInfoPtr pInfo;
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    dbus_int32_t major = _major;
    dbus_int32_t minor = _minor;
    int matches = 0;

    if (!info->session_object_path || major == 0)
        goto close;

    /* Only release the fd if there is only 1 InputInfo left for this major
     * and minor, otherwise other InputInfo's are still referencing the fd. */
    pInfo = systemd_logind_find_info_ptr_by_devnum(xf86InputDevs, major, minor);
    while (pInfo) {
        matches++;
        pInfo = systemd_logind_find_info_ptr_by_devnum(pInfo->next, major, minor);
    }
    if (matches > 1) {
        LogMessage(X_INFO, "systemd-logind: not releasing fd for %u:%u, still in use\n", major, minor);
        return;
    }

    LogMessage(X_INFO, "systemd-logind: releasing fd for %u:%u\n", major, minor);

    dbus_error_init(&error);

    msg = dbus_message_new_method_call("org.freedesktop.login1", info->session_object_path,
            "org.freedesktop.login1.Session", "ReleaseDevice");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    if (!dbus_message_append_args(msg, DBUS_TYPE_UINT32, &major,
                                       DBUS_TYPE_UINT32, &minor,
                                       DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply)
        LogMessage(X_ERROR, "systemd-logind: failed to release device: %s\n",
                   error.message);

cleanup:
    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);
close:
    if (fd != -1)
        close(fd);
}

int
systemd_logind_controls_session(void)
{
    return logind_info.session_object_path ? 1 : 0;
}

void
systemd_logind_vtenter(void)
{
    struct systemd_logind_info *info = &logind_info;
    InputInfoPtr pInfo;
    int i;

    if (!info->session_object_path)
        return; /* Not using systemd-logind */

    if (!info->active)
        return; /* Session not active */

    if (info->vt_active)
        return; /* Already did vtenter */

    for (i = 0; i < xf86_num_platform_devices; i++) {
        if (xf86_platform_devices[i].flags & XF86_PDEV_PAUSED)
            break;
    }
    if (i != xf86_num_platform_devices)
        return; /* Some drm nodes are still paused wait for resume */

    xf86VTEnter();
    info->vt_active = TRUE;

    /* Activate any input devices which were resumed before the drm nodes */
    for (pInfo = xf86InputDevs; pInfo; pInfo = pInfo->next)
        if ((pInfo->flags & XI86_SERVER_FD) && pInfo->fd != -1)
            xf86EnableInputDeviceForVTSwitch(pInfo);

    /* Do delayed input probing, this must be done after the above enabling */
    xf86InputEnableVTProbe();
}

static void
systemd_logind_ack_pause(struct systemd_logind_info *info,
                         dbus_int32_t minor, dbus_int32_t major)
{
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;

    dbus_error_init(&error);

    msg = dbus_message_new_method_call("org.freedesktop.login1", info->session_object_path,
            "org.freedesktop.login1.Session", "PauseDeviceComplete");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    if (!dbus_message_append_args(msg, DBUS_TYPE_UINT32, &major,
                                       DBUS_TYPE_UINT32, &minor,
                                       DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply)
        LogMessage(X_ERROR, "systemd-logind: failed to ack pause: %s\n",
                   error.message);

cleanup:
    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);
}

static void
detach_from_session(struct systemd_logind_info *info)
{

    if (info->session_object_path != NULL) {
        systemd_logind_release_control(info);

        free (info->session_object_path);
        info->session_object_path = NULL;
    }

    free (info->session_id);
    info->session_id = NULL;
}

static DBusHandlerResult
message_filter(DBusConnection * connection, DBusMessage * message, void *data)
{
    struct systemd_logind_info *info = data;
    struct xf86_platform_device *pdev = NULL;
    InputInfoPtr pInfo = NULL;
    int ack = 0, pause = 0, fd = -1;
    DBusError error;
    dbus_int32_t major, minor;
    char *pause_str;

    dbus_error_init(&error);

    if (dbus_message_is_signal(message,
                               "org.freedesktop.DBus", "NameOwnerChanged")) {
        char *name, *old_owner, *new_owner;

        dbus_message_get_args(message, &error,
                              DBUS_TYPE_STRING, &name,
                              DBUS_TYPE_STRING, &old_owner,
                              DBUS_TYPE_STRING, &new_owner, DBUS_TYPE_INVALID);
        if (dbus_error_is_set(&error)) {
            LogMessage(X_ERROR, "systemd-logind: NameOwnerChanged: %s\n",
                       error.message);
            dbus_error_free(&error);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        if (name && strcmp(name, "org.freedesktop.login1") == 0)
            FatalError("systemd-logind disappeared (stopped/restarted?)\n");

        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (info->session_object_path == NULL)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (strcmp(dbus_message_get_path(message), info->session_object_path) != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (dbus_message_is_signal(message, "org.freedesktop.login1.Session",
                               "PauseDevice")) {
        if (!dbus_message_get_args(message, &error,
                               DBUS_TYPE_UINT32, &major,
                               DBUS_TYPE_UINT32, &minor,
                               DBUS_TYPE_STRING, &pause_str,
                               DBUS_TYPE_INVALID)) {
            LogMessage(X_ERROR, "systemd-logind: PauseDevice: %s\n",
                       error.message);
            dbus_error_free(&error);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }

        if (strcmp(pause_str, "pause") == 0) {
            pause = 1;
            ack = 1;
        }
        else if (strcmp(pause_str, "force") == 0) {
            pause = 1;
        }
        else if (strcmp(pause_str, "gone") == 0) {
            /* Device removal is handled through udev */
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
        else {
            LogMessage(X_WARNING, "systemd-logind: unknown pause type: %s\n",
                       pause_str);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
    }
    else if (dbus_message_is_signal(message, "org.freedesktop.login1.Session",
                                    "ResumeDevice")) {
        if (!dbus_message_get_args(message, &error,
                                   DBUS_TYPE_UINT32, &major,
                                   DBUS_TYPE_UINT32, &minor,
                                   DBUS_TYPE_UNIX_FD, &fd,
                                   DBUS_TYPE_INVALID)) {
            LogMessage(X_ERROR, "systemd-logind: ResumeDevice: %s\n",
                       error.message);
            dbus_error_free(&error);
            return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
        }
    } else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    LogMessage(X_INFO, "systemd-logind: got %s for %u:%u\n",
               pause ? "pause" : "resume", major, minor);

    pdev = xf86_find_platform_device_by_devnum(major, minor);
    if (!pdev)
        pInfo = systemd_logind_find_info_ptr_by_devnum(xf86InputDevs,
                                                       major, minor);
    if (!pdev && !pInfo) {
        LogMessage(X_WARNING, "systemd-logind: could not find dev %u:%u\n",
                   major, minor);
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    if (pause) {
        /* Our VT_PROCESS usage guarantees we've already given up the vt */
        info->active = info->vt_active = FALSE;
        /* Note the actual vtleave has already been handled by xf86Events.c */
        if (pdev)
            pdev->flags |= XF86_PDEV_PAUSED;
        else {
            close(pInfo->fd);
            systemd_logind_set_input_fd_for_all_devs(major, minor, -1, FALSE);
        }
        if (ack)
            systemd_logind_ack_pause(info, major, minor);
    }
    else {
        /* info->vt_active gets set by systemd_logind_vtenter() */
        info->active = TRUE;

        if (pdev)
            pdev->flags &= ~XF86_PDEV_PAUSED;
        else
            systemd_logind_set_input_fd_for_all_devs(major, minor, fd,
                                                     info->vt_active);

        /* Always call vtenter(), in case there are only legacy video devs */
        systemd_logind_vtenter();
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}

static int
validate_session(struct systemd_logind_info *info, const char *session,
                 const char *requested_type, unsigned int *vt)
{
    int ret;
    char *state = NULL, *type = NULL, *seat = NULL;

    ret = sd_session_get_state(session, &state);

    if (ret < 0 || state == NULL) {
        goto out;
    }

    if (strcmp(state, "closing") == 0) {
        ret = -ENOENT;
        goto out;
    }

    if (requested_type != NULL) {
        ret = sd_session_get_type(session, &type);

        if (ret < 0 || type == NULL) {
            goto out;
        }

        if (strcmp(type, requested_type) != 0) {
            ret = -ENOENT;
            goto out;
        }
    }

    ret = sd_session_get_seat(session, &seat);

    if (ret < 0 || seat == NULL) {
        goto out;
    }

    if (strcmp(seat, "seat0") != 0) {
        ret = -ENOENT;
        goto out;
    }

    ret = sd_session_get_vt(session, vt);

    if (ret < 0 || *vt <= 0) {
        goto out;
    }

    if (xf86Info.vtno != -1 && xf86Info.vtno != *vt) {
        ret = -ENOENT;
        goto out;
    }

    ret = 0;

out:
    free(state);
    free(type);
    free(seat);
    return ret;
}

static char *
find_session_id_by_type(struct systemd_logind_info *info, const char * const * sessions,
                        const char *requested_type, unsigned int *vt)
{
    int ret;
    int i;

    for (i = 0; sessions[i] != NULL; i++) {
        ret = validate_session(info, sessions[i], requested_type, vt);
        if (ret == 0) {
            return strdup(sessions[i]);
        }
    }

    return NULL;
}

static char *
get_object_path_for_session(struct systemd_logind_info *info, const char *session)
{
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    char *session_object_path = NULL;

    dbus_error_init(&error);
    msg = dbus_message_new_method_call("org.freedesktop.login1",
                                       "/org/freedesktop/login1", "org.freedesktop.login1.Manager",
                                       "GetSession");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    if (!dbus_message_append_args(msg, DBUS_TYPE_STRING, &session,
                                  DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply) {
        LogMessage(X_ERROR, "systemd-logind: failed to get session: %s\n",
                   error.message);
        goto cleanup;
    }

    if (!dbus_message_get_args(reply, &error, DBUS_TYPE_OBJECT_PATH, &session_object_path,
                               DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: GetSession: %s\n",
                   error.message);
        goto cleanup;
    }
    session_object_path = XNFstrdup(session_object_path);

cleanup:
    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);

    return session_object_path;
}

static char *
find_session_id(struct systemd_logind_info *info, unsigned int *vt)
{
    char *session = NULL;
    int ret;

    if (!SocketActivated) {
        ret = sd_pid_get_session(getpid(), &session);

        if (ret == 0) {
            ret = validate_session(info, session, NULL, vt);

            if (ret == 0) {
                goto out;
            }

            free(session);
            session = NULL;
        }
    } else {
        char **sessions = NULL;
        int i;

        ret = sd_uid_get_sessions(getuid(), FALSE, &sessions);

        if (ret < 0 || sessions == NULL) {
            goto out;
        }

        session = find_session_id_by_type(info, (const char * const *) sessions, "x11", vt);

        for (i = 0; sessions[i] != NULL; i++) {
            free(sessions[i]);
        }
        free(sessions);
    }

out:
    return session;
}

static Bool
attach_to_session(struct systemd_logind_info *info, const char *session_id, unsigned int vt)
{
    Bool result = FALSE;
    char *session_object_path = NULL;
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;
    dbus_int32_t arg;

    dbus_error_init(&error);

    session_object_path = get_object_path_for_session(info, session_id);

    if (!session_object_path) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    msg = dbus_message_new_method_call("org.freedesktop.login1",
                                       session_object_path,
                                       "org.freedesktop.login1.Session",
                                       "TakeControl");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    arg = FALSE; /* Don't forcibly take over over the session */
    if (!dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &arg,
                                  DBUS_TYPE_INVALID)) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply) {
        LogMessage(X_ERROR, "systemd-logind: TakeControl iailed: %s\n",
                   error.message);
        goto cleanup;
    }

    info->session_id = strdup(session_id);

    if (!info->session_id) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    LogMessage(X_INFO, "systemd-logind: took control of session %s\n",
               session_id);
    info->session_object_path = session_object_path;
    xf86Info.vtno = vt;
    info->vt_active = info->active = TRUE; /* The server owns the vt during init */
    session_object_path = NULL;
    session_id = NULL;

    result = TRUE;

cleanup:
    free(session_object_path);

    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);

    return result;
}

static void
wakeup_handler(void *data, int result, void *read_mask)
{
    struct systemd_logind_info *info = data;
    int fd;

    if (result <= 0)
        return;

    fd = sd_login_monitor_get_fd(info->login_monitor);
    if (FD_ISSET(fd, (fd_set *) read_mask)) {
        char *state = NULL;
        int ret;

        sd_login_monitor_flush (info->login_monitor);

        if (info->session_id != NULL) {
            ret = sd_session_get_state(info->session_id, &state);

            if (ret < 0 || state == NULL ||
                (strcmp(state, "closing") == 0) ||
                (strcmp(state, "offline") == 0)) {
                LogMessage(X_INFO, "systemd-logind: attached session closing, killing all clients and waiting for new session\n");
                systemd_logind_release_control(info);
                detach_from_session(info);

                Deactivate();
            }
        } else {
            unsigned int vt = 0;
            char *session_id;

            session_id = find_session_id(info, &vt);

            if (session_id) {
                LogMessage(X_INFO, "systemd-logind: new session %s available, attaching and regenerating\n", session_id);
                if (attach_to_session(info, session_id, vt)) {
                    Reactivate();
                } else {
                    LogMessage(X_WARNING, "systemd-logind: could not attach to new session\n");
                    free(session_id);
                }
            }
        }
    }
}

static void
block_handler(void *data, struct timeval **tv, void *read_mask)
{
}

static void
connect_hook(DBusConnection *connection, void *data)
{
    struct systemd_logind_info *info = data;
    char *session_id = NULL;
    unsigned int vt = 0;
    sd_login_monitor *login_monitor = NULL;
    DBusError error;
    int ret;

    dbus_error_init(&error);

    info->conn = connection;

    session_id = find_session_id(info, &vt);

    if (!session_id) {
        LogMessage(X_ERROR, "systemd-logind: couldn't find session to take control of\n");
        goto cleanup;
    }

    if (!attach_to_session(info, session_id, vt)) {
        goto cleanup;
    }

    dbus_bus_add_match(info->conn,
        "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',path='/org/freedesktop/DBus'",
        &error);

    if (dbus_error_is_set(&error)) {
        LogMessage(X_ERROR, "systemd-logind: could not add match: %s\n",
                   error.message);
        goto cleanup;
    }

    if (!dbus_connection_add_filter(connection, message_filter, info, NULL)) {
        LogMessage(X_ERROR, "systemd-logind: could not add filter: %s\n",
                   error.message);
        goto cleanup;
    }

    if (SocketActivated) {
        ret = sd_login_monitor_new(NULL, &login_monitor);

        if (ret < 0) {
            LogMessage(X_ERROR, "systemd-logind: could not add monitor: %s\n",
                       strerror(-ret));
            goto cleanup;
        }
        AddGeneralSocket(sd_login_monitor_get_fd(login_monitor));
        RegisterBlockAndWakeupHandlers(block_handler, wakeup_handler, info);

        info->login_monitor = login_monitor;

        login_monitor = NULL;
    }

cleanup:
    free(session_id);

    if (login_monitor)
        sd_login_monitor_unref(login_monitor);
    dbus_error_free(&error);
}

static void
systemd_logind_release_control(struct systemd_logind_info *info)
{
    DBusError error;
    DBusMessage *msg = NULL;
    DBusMessage *reply = NULL;

    dbus_error_init(&error);

    msg = dbus_message_new_method_call("org.freedesktop.login1",
            info->session_object_path, "org.freedesktop.login1.Session", "ReleaseControl");
    if (!msg) {
        LogMessage(X_ERROR, "systemd-logind: out of memory\n");
        goto cleanup;
    }

    reply = dbus_connection_send_with_reply_and_block(info->conn, msg,
                                                      DBUS_TIMEOUT, &error);
    if (!reply) {
        LogMessage(X_ERROR, "systemd-logind: ReleaseControl failed: %s\n",
                   error.message);
        goto cleanup;
    }

cleanup:
    if (msg)
        dbus_message_unref(msg);
    if (reply)
        dbus_message_unref(reply);
    dbus_error_free(&error);
}

static void
disconnect_hook(void *data)
{
    struct systemd_logind_info *info = data;

    detach_from_session(info);

    if (info->login_monitor) {
        RemoveBlockAndWakeupHandlers(block_handler, wakeup_handler, info);
        RemoveGeneralSocket(sd_login_monitor_get_fd(info->login_monitor));

        sd_login_monitor_unref(info->login_monitor);
        info->login_monitor = NULL;
    }

    info->conn = NULL;
}

static struct dbus_core_hook core_hook = {
    .connect = connect_hook,
    .disconnect = disconnect_hook,
    .data = &logind_info,
};

int
systemd_logind_init(void)
{
    struct systemd_logind_info *info = &logind_info;

    if (!hook_added) {
        hook_added = dbus_core_add_hook(&core_hook);
    } else {
        if (info->login_monitor) {
            /* On server reset, wakeup handlers are cleared, so reregister ours now */
            RemoveBlockAndWakeupHandlers(block_handler, wakeup_handler, &logind_info);
            RegisterBlockAndWakeupHandlers(block_handler, wakeup_handler, &logind_info);
        }
    }

    return hook_added;
}

void
systemd_logind_fini(void)
{
    if (logind_info.session_object_path)
        systemd_logind_release_control(&logind_info);

    dbus_core_remove_hook(&core_hook);
    hook_added = FALSE;
}
