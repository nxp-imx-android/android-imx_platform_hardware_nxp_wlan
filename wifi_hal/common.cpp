/*
* Copyright (C) 2017 The Android Open Source Project
* Portions copyright (C) 2017 Broadcom Limited
* Portions copyright 2015-2020 NXP
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>

#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include "common.h"
#include "cpp_bindings.h"

interface_info *getIfaceInfo(wifi_interface_handle handle)
{
    return (interface_info *)handle;
}

wifi_handle getWifiHandle(wifi_interface_handle handle)
{
    return getIfaceInfo(handle)->handle;
}

hal_info *getHalInfo(wifi_handle handle)
{
    return (hal_info *)handle;
}

hal_info *getHalInfo(wifi_interface_handle handle)
{
    return getHalInfo(getWifiHandle(handle));
}

wifi_handle getWifiHandle(hal_info *info)
{
    return (wifi_handle)info;
}

wifi_interface_handle getIfaceHandle(interface_info *info)
{
    return (wifi_interface_handle)info;
}

wifi_error wifi_register_handler(wifi_handle handle, int cmd, nl_recvmsg_msg_cb_t func, void *arg)
{
    hal_info *info = (hal_info *)handle;

    /* TODO: check for multiple handlers? */
    pthread_mutex_lock(&info->cb_lock);

    wifi_error result = WIFI_ERROR_OUT_OF_MEMORY;

    if (info->num_event_cb < info->alloc_event_cb) {
        info->event_cb[info->num_event_cb].nl_cmd  = cmd;
        info->event_cb[info->num_event_cb].vendor_id  = 0;
        info->event_cb[info->num_event_cb].vendor_subcmd  = 0;
        info->event_cb[info->num_event_cb].cb_func = func;
        info->event_cb[info->num_event_cb].cb_arg  = arg;
        ALOGV("Successfully added event handler %p:%p for command %d at %d",
                arg, func, cmd, info->num_event_cb);
        info->num_event_cb++;
        result = WIFI_SUCCESS;
    }

    pthread_mutex_unlock(&info->cb_lock);
    return result;
}

wifi_error wifi_register_vendor_handler(wifi_handle handle,
        uint32_t id, int subcmd, nl_recvmsg_msg_cb_t func, void *arg)
{
    hal_info *info = (hal_info *)handle;

    /* TODO: check for multiple handlers? */
    pthread_mutex_lock(&info->cb_lock);

    wifi_error result = WIFI_ERROR_OUT_OF_MEMORY;

    if (info->num_event_cb < info->alloc_event_cb) {
        info->event_cb[info->num_event_cb].nl_cmd  = NL80211_CMD_VENDOR;
        info->event_cb[info->num_event_cb].vendor_id  = id;
        info->event_cb[info->num_event_cb].vendor_subcmd  = subcmd;
        info->event_cb[info->num_event_cb].cb_func = func;
        info->event_cb[info->num_event_cb].cb_arg  = arg;
        ALOGV("Added event handler %p:%p for vendor 0x%0x and subcmd 0x%0x at %d",
                arg, func, id, subcmd, info->num_event_cb);
        info->num_event_cb++;
        result = WIFI_SUCCESS;
    }

    pthread_mutex_unlock(&info->cb_lock);
    return result;
}

void wifi_unregister_handler(wifi_handle handle, int cmd)
{
    hal_info *info = (hal_info *)handle;

    if (cmd == NL80211_CMD_VENDOR) {
        ALOGE("Must use wifi_unregister_vendor_handler to remove vendor handlers");
        return;
    }

    pthread_mutex_lock(&info->cb_lock);

    for (int i = 0; i < info->num_event_cb; i++) {
        if (info->event_cb[i].nl_cmd == cmd) {
            ALOGV("Successfully removed event handler %p:%p for cmd = 0x%0x from %d",
                    info->event_cb[i].cb_arg, info->event_cb[i].cb_func, cmd, i);

            memmove(&info->event_cb[i], &info->event_cb[i+1],
                (info->num_event_cb - i - 1) * sizeof(cb_info));
            info->num_event_cb--;
            break;
        }
    }

    pthread_mutex_unlock(&info->cb_lock);
}

void wifi_unregister_vendor_handler(wifi_handle handle, uint32_t id, int subcmd)
{
    hal_info *info = (hal_info *)handle;

    pthread_mutex_lock(&info->cb_lock);

    for (int i = 0; i < info->num_event_cb; i++) {

        if (info->event_cb[i].nl_cmd == NL80211_CMD_VENDOR
                && info->event_cb[i].vendor_id == id
                && info->event_cb[i].vendor_subcmd == subcmd) {
            ALOGV("Successfully removed event handler %p:%p for vendor 0x%0x, subcmd 0x%0x from %d",
                    info->event_cb[i].cb_arg, info->event_cb[i].cb_func, id, subcmd, i);
            memmove(&info->event_cb[i], &info->event_cb[i+1],
                (info->num_event_cb - i - 1) * sizeof(cb_info));
            info->num_event_cb--;
            break;
        }
    }

    pthread_mutex_unlock(&info->cb_lock);
}


wifi_error wifi_register_cmd(wifi_handle handle, int id, WifiCommand *cmd)
{
    hal_info *info = (hal_info *)handle;

    ALOGI("registering command %d", id);

    wifi_error result = WIFI_ERROR_OUT_OF_MEMORY;

    ALOGV("%s()::%d::Reached!!\n", __func__, __LINE__);	
    if (info->num_cmd < info->alloc_cmd) {
        info->cmd[info->num_cmd].id   = id;
        info->cmd[info->num_cmd].cmd  = cmd;
        ALOGV("Successfully added command %d: %p at %d", id, cmd, info->num_cmd);
        ALOGV("%s()::%d::Reached!!\n", __func__, __LINE__);
        info->num_cmd++;
        result = WIFI_SUCCESS;
    }

    return result;
}

WifiCommand *wifi_unregister_cmd(wifi_handle handle, int id)
{
    hal_info *info = (hal_info *)handle;

    ALOGV("un-registering command %d", id);

    WifiCommand *cmd = NULL;

    for (int i = 0; i < info->num_cmd; i++) {
        if (info->cmd[i].id == id) {
            cmd = info->cmd[i].cmd;
            memmove(&info->cmd[i], &info->cmd[i+1], (info->num_cmd - i - 1) * sizeof(cmd_info));
            info->num_cmd--;
            ALOGV("Successfully removed command %d: %p from %d", id, cmd, i);
            break;
        }
    }

    return cmd;
}

WifiCommand *wifi_get_cmd(wifi_handle handle, int id)
{
    hal_info *info = (hal_info *)handle;

    WifiCommand *cmd = NULL;

    for (int i = 0; i < info->num_cmd; i++) {
        if (info->cmd[i].id == id) {
            cmd = info->cmd[i].cmd;
            break;
        }
    }

    return cmd;
}

void wifi_unregister_cmd(wifi_handle handle, WifiCommand *cmd)
{
    hal_info *info = (hal_info *)handle;

    for (int i = 0; i < info->num_cmd; i++) {
        if (info->cmd[i].cmd == cmd) {
            int id = info->cmd[i].id;
            memmove(&info->cmd[i], &info->cmd[i+1], (info->num_cmd - i - 1) * sizeof(cmd_info));
            info->num_cmd--;
            ALOGV("Successfully removed command %d: %p from %d", id, cmd, i);
            break;
        }
    }
}

wifi_error wifi_cancel_cmd(wifi_request_id id, wifi_interface_handle iface)
{
    wifi_handle handle = getWifiHandle(iface);

    WifiCommand *cmd = wifi_unregister_cmd(handle, id);
    ALOGV("Cancel WifiCommand = %p", cmd);
    if (cmd) {
        cmd->cancel();
        cmd->releaseRef();
        return WIFI_SUCCESS;
    }

    return WIFI_ERROR_INVALID_ARGS;
}

void hexdump(void *buf, byte len)
{
    int i=0;
    char *bytes = (char *)buf;

    if (len) {
        ALOGV("******HexDump len:%d*********", len);
        for (i = 0; ((i + 7) < len); i+=8) {
            ALOGV("%02x %02x %02x %02x   %02x %02x %02x %02x",
                bytes[i], bytes[i+1],
                bytes[i+2], bytes[i+3],
                bytes[i+4], bytes[i+5],
                bytes[i+6], bytes[i+7]);
        }
        if ((len - i) >= 4) {
            ALOGV("%02x %02x %02x %02x",
                bytes[i], bytes[i+1],
                bytes[i+2], bytes[i+3]);
            i+=4;
        }
        for (;i < len;i++) {
            ALOGV("%02x", bytes[i]);
        }
        ALOGV("******HexDump End***********");
    } else {
        return;
    }
}

#if defined(NXP_VHAL_PRIV_CMD)
int prepare_buffer(u8 *buffer, char* cmd, u32 num, char *args[])
{
    u8 *pos = NULL;
    unsigned int i = 0;

    memset(buffer, 0, BUFFER_LENGTH);

    /* Flag it for our use */
    pos = buffer;
    memcpy((char *)pos, CMD_NXP, strlen(CMD_NXP));
    pos += (strlen(CMD_NXP));

    /* Insert command */
    strncpy((char *)pos, (char *)cmd, strlen(cmd));
    pos += (strlen(cmd));

    /* Insert arguments */
    for (i = 0; i < num; i++)
    {
        strncpy((char *)pos, args[i], strlen(args[i]));
        pos += strlen(args[i]);
        if (i < (num - 1)) {
            memcpy((char *)pos, " ", strlen(" "));
            pos += 1;
        }
    }

    return WIFI_SUCCESS;
}

/**
 *  @brief Convert char to hex integer
 *
 *  @param chr      Char
 *  @return         Hex integer
 */
u8 hexc2bin(char chr)
{
    if (chr >= '0' && chr <= '9')
        chr -= '0';
    else if (chr >= 'A' && chr <= 'F')
        chr -= ('A' - 10);
    else if (chr >= 'a' && chr <= 'f')
        chr -= ('a' - 10);

    return chr;
}

/**
 *  @brief Convert string to hex integer
 *
 *  @param s        A pointer string buffer
 *  @return         Hex integer
 */
u32 a2hex(char *s)
{
    u32    val = 0;

    if (!strncasecmp("0x", s, 2)) {
        s += 2;
    }

    while (*s && isxdigit((unsigned char)*s)) {
        val = (val << 4) + hexc2bin(*s++);
    }

    return val;
}


/*
 *  @brief Convert String to integer
 *
 *  @param value    A pointer to string
 *  @return         Integer
 */
u32 a2hex_or_atoi(char *value)
{
    if (value[0] == '0' && (value[1] == 'X' || value[1] == 'x')) {
        return a2hex(value + 2);
    } else {
        return (u32)atoi(value);
    }
}

/**
 *  @brief Get one line from the File
 *
 *  @param fp       File handler
 *  @param str      Storage location for data.
 *  @param size     Maximum number of characters to read.
 *  @param lineno   A pointer to return current line number
 *  @return         returns string or NULL
 */
char *config_get_line(FILE* fp, char *str, int32_t size, int *lineno)
{
    char *start, *end;
    int out, next_line;

    if (!fp || !str)
        return NULL;

    do {
read_line:
        if (!fgets(str, size, fp))
            break;
        start = str;
        start[size - 1] = '\0';
        end = start + strlen(str);
        (*lineno)++;

        out = 1;
        while (out && (start < end)) {
            next_line = 0;
            /* Remove empty lines and lines starting with # */
            switch (start[0]) {
            case ' ':  /* White space */
            case '\t': /* Tab */
                start ++;
                break;
            case '#':
            case '\n':
            case '\0':
                next_line = 1;
                break;
            case '\r':
                if (start[1] == '\n')
                    next_line = 1;
                else
                    start ++;
                break;
            default:
                out = 0;
                break;
            }
            if (next_line)
                goto read_line;
        }

        /* Remove # comments unless they are within a double quoted
         * string. Remove trailing white space. */
        end = strstr(start, "\"");
        if (end) {
            end = strstr(end + 1, "\"");
            if (!end)
                end = start;
        } else
            end = start;

        end = strstr(end + 1, "#");
        if (end)
            *end-- = '\0';
        else
            end = start + strlen(start) - 1;

        out = 1;
        while (out && (start < end)) {
            switch (*end) {
            case ' ':  /* White space */
            case '\t': /* Tab */
            case '\n':
            case '\r':
                *end = '\0';
                end --;
                break;
            default:
                out = 0;
                break;
            }
        }

        if (*start == '\0')
            continue;

        return start;
    } while(1);

    return NULL;
}

/**
 *  @brief get hostcmd data
 *
 *  @param ln           A pointer to line number
 *  @param buf          A pointer to hostcmd data
 *  @param size         A pointer to the return size of hostcmd buffer
 *  @return             WIFI_STATUS_SUCCESS
 */
static int get_hostcmd_data(FILE *fp, int *ln, u8 *buf, u16 *size)
{
    int32_t errors = 0, i;
    char  line[512], *pos, *pos1, *pos2, *pos3;
    u16  len;


    while ((pos = config_get_line(fp, line, sizeof(line), ln))) {
        (*ln)++;
        if (strcmp(pos, "}") == 0) {
            break;
        }

        pos1 = strchr(pos, ':');
        if (pos1 == NULL) {
            ALOGE("Line %d: Invalid hostcmd line '%s'", *ln, pos);
            errors++;
            continue;
        }
        *pos1++ = '\0';

        pos2 = strchr(pos1, '=');
        if (pos2 == NULL) {
            ALOGE("Line %d: Invalid hostcmd line '%s'", *ln, pos);
            errors++;
            continue;
        }
        *pos2++ = '\0';

        len = a2hex_or_atoi(pos1);
        if (len < 1 || len > BUFFER_LENGTH) {
            ALOGE("Line %d: Invalid hostcmd line '%s'", *ln, pos);
            errors++;
            continue;
        }

        *size += len;

        if (*pos2 == '"') {
            pos2++;
            pos3 = strchr(pos2, '"');
            if (pos3 == NULL) {
                ALOGE("Line %d: invalid quotation '%s'", *ln, pos);
                errors++;
                continue;
            }
            *pos3 = '\0';
            memset(buf, 0, len);
            memmove(buf, pos2, min(strlen(pos2),len));
            buf += len;
        }
        else if (*pos2 == '\'') {
            pos2++;
            pos3 = strchr(pos2, '\'');
            if (pos3 == NULL) {
                ALOGE("Line %d: invalid quotation '%s'", *ln, pos);
                errors++;
                continue;
            }
            *pos3 = ',';
            for (i=0; i<len; i++) {
                pos3 = strchr(pos2, ',');
                if (pos3 != NULL) {
                    *pos3 = '\0';
                    *buf++ = (u8)a2hex_or_atoi(pos2);
                    pos2 = pos3 + 1;
                }
                else
                    *buf++ = 0;
            }
        }
        else if (*pos2 == '{') {
            u16 tlvlen = 0, tmp_tlvlen;
            get_hostcmd_data(fp, ln, buf+len, &tlvlen);
            tmp_tlvlen = tlvlen;
            while (len--) {
                *buf++ = (u8)(tmp_tlvlen & 0xff);
                tmp_tlvlen >>= 8;
            }
            *size += tlvlen;
            buf += tlvlen;
        }
        else {
            u32 value = a2hex_or_atoi(pos2);
            while (len--) {
                *buf++ = (u8)(value & 0xff);
                value >>= 8;
            }
        }
    }
    return WIFI_SUCCESS;
}

/**
 *  @brief Prepare host-command buffer
 *  @param fp       File handler
 *  @param cmd_name Command name
 *  @param buf      A pointer to comand buffer
 *  @return         WIFI_SUCCESS--success, otherwise--fail
 */
int prepare_host_cmd_buffer(FILE* fp, char *cmd_name, u8 *buf)
{
    char line[256], cmdname[256], *pos, cmdcode[10];
    HostCmd_DS_GEN  *hostcmd;
    u32 hostcmd_size = 0;
    int ln = 0;
    int cmdname_found = 0, cmdcode_found = 0;

    hostcmd = (HostCmd_DS_GEN *)(buf + sizeof(u32));
    hostcmd->command = 0xffff;

    snprintf(cmdname, sizeof(cmdname), "%s={", cmd_name);
    ALOGD("prepare_host_cmd_buffer: Cmdname is %s", cmdname);
    cmdname_found = 0;
    while ((pos = config_get_line(fp, line, sizeof(line), &ln))) {
        if (strcmp(pos, cmdname) == 0) {
            cmdname_found = 1;
            snprintf(cmdcode, sizeof(cmdcode), "CmdCode=");
            cmdcode_found = 0;
            while ((pos = config_get_line(fp, line, sizeof(line), &ln))) {
                if (strncmp(pos, cmdcode, strlen(cmdcode)) == 0) {
                    u16 len = 0;
                    cmdcode_found = 1;
                    hostcmd->command = a2hex_or_atoi(pos+strlen(cmdcode));
                    hostcmd->size = S_DS_GEN;
                    get_hostcmd_data(fp, &ln, buf + sizeof(u32) + hostcmd->size, &len);
                    hostcmd->size += len;
                    break;
                }
            }
            if (!cmdcode_found) {
                ALOGE("prepare_host_cmd_buffer: CmdCode not found in conf file");
                return WIFI_ERROR_UNKNOWN;
            }
            break;
        }
    }

    if (!cmdname_found) {
        ALOGE("prepare_host_cmd_buffer: cmdname '%s' is not found in conf file\n", cmd_name);
        return WIFI_ERROR_UNKNOWN;
    }

    hostcmd->seq_num = 0;
    hostcmd->result = 0;

    hostcmd_size = (u32)(hostcmd->size);
    memcpy(buf, (u8 *)&hostcmd_size, sizeof(u32));

    return WIFI_SUCCESS;
}
/**
 *  @brief Process host_cmd response
 *  @param cmd_name Command name
 *  @param buf      A pointer to the response buffer
 *  @return         WIFI_SUCCESS--success, otherwise--fail
 */
int process_host_cmd_resp(char *cmd_name, u8 *buf)
{
    u32 hostcmd_size = 0;
    HostCmd_DS_GEN  *hostcmd = NULL;
    int ret = WIFI_SUCCESS;
    ed_mac_ctrl ed_ctrl;

    buf += strlen(CMD_NXP) + strlen(cmd_name);
    memcpy((u8 *)&hostcmd_size, buf, sizeof(u32));
    buf += sizeof(u32);

    hostcmd = (HostCmd_DS_GEN *)buf;

    hostcmd->command &= ~HostCmd_RET_BIT;
    if (!hostcmd->result) {
        switch (hostcmd->command) {
       case HostCmd_CMD_ED_CTRL:
            /*
             * Read/Write EDMAC control parameters.
             */
            ALOGI("HOSTCMD_RESP: CmdCode=%#04x, Size=%#04x,"
                   " SeqNum=%#04x, Result=%#04x\n",
                   hostcmd->command, hostcmd->size,
                   hostcmd->seq_num, hostcmd->result);
            hexdump((void *)(buf+S_DS_GEN), hostcmd->size-S_DS_GEN);

            memcpy(&ed_ctrl, buf+S_DS_GEN, sizeof(struct _ed_mac_ctrl));
            ALOGI("edmac_2G:0x%02x\noffset_2G:0x%02x\n"
                   "edmac_5G:0x%02x\noffset_5G:0x%02x\n"
                   "\n",
                   ed_ctrl.ed_ctrl_2g, ed_ctrl.ed_offset_2g,
                   ed_ctrl.ed_ctrl_5g, ed_ctrl.ed_offset_5g
                  );
            break;
        default:
            ALOGE("HOSTCMD_RESP: CmdCode=%#04x, Size=%#04x,"
                   " SeqNum=%#04x, Result=%#04x\n",
                   hostcmd->command, hostcmd->size,
                   hostcmd->seq_num, hostcmd->result);
            hexdump((void *)(buf+S_DS_GEN), hostcmd->size-S_DS_GEN);
            break;
        }
    } else {
        ALOGE("HOSTCMD failed: CmdCode=%#04x, Size=%#04x,"
               " SeqNum=%#04x, Result=%#04x\n",
               hostcmd->command, hostcmd->size,
               hostcmd->seq_num, hostcmd->result);
    }
    return ret;
}

#endif //NXP_VHAL_PRIV_CMD
