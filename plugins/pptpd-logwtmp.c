/*
 * $Id: pptpd-logwtmp.c,v 1.5 2007/04/16 00:21:02 quozl Exp $
 * pptpd-logwtmp.c - pppd plugin to update wtmp for a pptpd user
 *
 * Copyright 2004 James Cameron.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <utmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include "pppd.h"

char pppd_version[] = VERSION;

static char pptpd_original_ip[PATH_MAX+1];
static bool pptpd_logwtmp_strip_domain = 0;

static option_t options[] = {
  { "pptpd-original-ip", o_string, pptpd_original_ip,
    "Original IP address of the PPTP connection",
    OPT_STATIC, NULL, PATH_MAX },
  { "pptpd-logwtmp-strip-domain", o_bool, &pptpd_logwtmp_strip_domain,
    "Strip domain from username before logging", OPT_PRIO | 1 },
  { NULL }
};

static char *reduce(char *user)
{
  char *sep;
  if (!pptpd_logwtmp_strip_domain) return user;

  sep = strstr(user, "//"); /* two slash */
  if (sep != NULL) user = sep + 2;
  sep = strstr(user, "\\"); /* or one backslash */
  if (sep != NULL) user = sep + 1;
  return user;
}

static void write_to_log(const char* log_name, char* buf, int len)
{
  int fd;
  fd = open(log_name, O_WRONLY|O_APPEND, 0644);
  if (fd == -1) {
    syslog(LOG_ERR, "Can not open %s", log_name);
    syslog(LOG_INFO, "%s", buf);
  } else {
    char time_str[64];
    int time_str_len;
    struct timeval tv;
    struct tm* logtm;
    gettimeofday(&tv, NULL);
    logtm = localtime(&tv.tv_sec);
    time_str_len = strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S %Z ", logtm);
    if (write(fd, time_str, time_str_len) == -1)
      syslog(LOG_ERR, "Write time string to log %s failed.", log_name);
    char pid_str[16];
    int pid = getpid();
    int pid_str_len =  sprintf(pid_str, "pppd[%d]: ", pid);
    if (write(fd, pid_str, pid_str_len) == -1)
      syslog(LOG_ERR, "Write pid %d to log %s failed.", pid, log_name);
    if (write(fd, buf, len) == -1)
      syslog(LOG_ERR, "Write buffer to log %s failed.", log_name);
    if (write(fd, "\n", 1) == -1)
      syslog(LOG_ERR, "Write line ending to log %s failed.", log_name);
    close(fd);
  }
}

static void ip_up(void *opaque, int arg)
{
  char *user = reduce(peer_authname);
  if (debug)
    notice("pptpd-logwtmp.so ip-up %s %s %s", ifname, user, 
	   pptpd_original_ip);
  logwtmp(ifname, user, pptpd_original_ip);
  char buf[128];
  int len;
  len = sprintf(buf, "START %s %s %s", ifname, user, pptpd_original_ip);
  write_to_log("/var/log/pptpd/monitor.log", buf, len);
}

static void ip_down(void *opaque, int arg)
{
  if (debug) 
    notice("pptpd-logwtmp.so ip-down %s", ifname);
  logwtmp(ifname, "", "");
  char buf[256];
  int len;
  char *user = reduce(peer_authname);
  len = sprintf(buf, "END %s %s %s sent %u bytes received %u bytes connect time %u seconds",
                ifname, user, pptpd_original_ip, link_stats.bytes_out, link_stats.bytes_in, link_connect_time);
  write_to_log("/var/log/pptpd/monitor.log", buf, len);
}

void plugin_init(void)
{
  add_options(options);
  add_notifier(&ip_up_notifier, ip_up, NULL);
  add_notifier(&ip_down_notifier, ip_down, NULL);
  if (debug) 
    notice("pptpd-logwtmp: $Version$");
}
