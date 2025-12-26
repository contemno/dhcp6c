/*	$KAME: dhcp6c_script.c,v 1.11 2004/11/28 10:48:38 jinmei Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
 * Copyright (C) 2023-2025 Franco Fichtner <franco@opnsense.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/stat.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <netinet/in.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "dhcp6.h"
#include "config.h"
#include "dhcp6c.h"
#include "common.h"

static char raw_dhcp_option_str[] = "raw_dhcp_option";

#define DECLARE_LIST(lname)	int lname##_len = 0;

#define COUNT_LIST(lname, lip)	do { \
	for (v = TAILQ_FIRST(&optinfo->lname##_list); v; \
	    v = TAILQ_NEXT(v, link)) { \
		/* one space separator plus address length or as is */ \
		lname##_len += 1 + ((lip) ? INET6_ADDRSTRLEN : lname##_len); \
	} \
	envc += lname##_len ? 1 : 0; \
} while (0)

#define RENDER_LIST(lname, lstr, lip)	do { \
	if (lname##_len) { \
		/* "var=" + null char for termination */ \
		int slen = sizeof(lstr) + 2 + lname##_len; \
		char *sptr; \
		if ((sptr = envp[i++] = malloc(slen)) == NULL) { \
			d_printf(LOG_NOTICE, FNAME, \
			    "failed to allocate strings for %s", lstr); \
			ret = -1; \
			goto clean; \
		} \
		memset(sptr, 0, slen); \
		snprintf(sptr, slen, "%s=", lstr); \
		for (v = TAILQ_FIRST(&optinfo->lname##_list); v; \
		    v = TAILQ_NEXT(v, link)) { \
			strlcat(sptr, (lip) ? in6addr2str(&v->val_addr6, 0) : \
			    v->val_vbuf.dv_buf, slen); \
			strlcat(sptr, " ", slen); \
		} \
	} \
} while (0)

int
client6_script(char *scriptpath, int state, struct dhcp6_optinfo *optinfo)
{
	int i, ret = 0;
	int envc = 2;	/* we at least include the reason and the terminator */
	int prefixes = 0, rawopts = 0;
	char **envp;
	char reason[32];
	char prefixinfo[32] = "\0";
	struct rawoption *rawopt;
	struct dhcp6_listval *v;
	pid_t pid, wpid;
	struct dhcp6_listval *iav, *siav;

	DECLARE_LIST(dns);
	DECLARE_LIST(dnsname);
	DECLARE_LIST(ntp);
	DECLARE_LIST(sip);
	DECLARE_LIST(sipname);
	DECLARE_LIST(nis);
	DECLARE_LIST(nisname);
	DECLARE_LIST(nisp);
	DECLARE_LIST(nispname);
	DECLARE_LIST(bcmcs);
	DECLARE_LIST(bcmcsname);
	DECLARE_LIST(aftrname);

	/* if a script is not specified, do nothing */
	if (scriptpath == NULL || strlen(scriptpath) == 0) {
		return -1;
	}

	d_printf(LOG_DEBUG, FNAME, "executes %s", scriptpath);

	if (state == DHCP6S_EXIT) {
		goto setenv;
	}

	COUNT_LIST(dns, 1);
	COUNT_LIST(dnsname, 0);
	COUNT_LIST(ntp, 1);
	COUNT_LIST(sip, 1);
	COUNT_LIST(sipname, 0);
	COUNT_LIST(nis, 1);
	COUNT_LIST(nisname, 0);
	COUNT_LIST(nisp, 1);
	COUNT_LIST(nispname, 0);
	COUNT_LIST(bcmcs, 1);
	COUNT_LIST(bcmcsname, 0);
	COUNT_LIST(aftrname, 0);

	for (iav = TAILQ_FIRST(&optinfo->iapd_list); iav;
	    iav = TAILQ_NEXT(iav, link)) {
		for (siav = TAILQ_FIRST(&iav->sublist); siav;
		    siav = TAILQ_NEXT(siav, link)) {
			if (siav->type == DHCP6_LISTVAL_PREFIX6) {
				prefixes += 1;
			}
		}
	}
	envc += prefixes ? 1 : 0;

	for (rawopt = TAILQ_FIRST(&optinfo->rawopt_list); rawopt;
	    rawopt = TAILQ_NEXT(rawopt, link)) {
		rawopts += 1;
	}
	envc += rawopts;

setenv:
	/* allocate an environments array */
	if ((envp = malloc(sizeof (char *) * envc)) == NULL) {
		d_printf(LOG_NOTICE, FNAME,
		    "failed to allocate environment buffer");
		return -1;
	}
	memset(envp, 0, sizeof(char *) * envc);

	/*
	 * Copy the parameters as environment variables
	 */

	{
		struct dhcp6_event ev;
		ev.state = state;
		snprintf(reason, sizeof(reason), "REASON=%s",
		    dhcp6_event_statestr(&ev));
	}

	i = 0;

	/* reason */
	if ((envp[i++] = strdup(reason)) == NULL) {
		d_printf(LOG_NOTICE, FNAME,
		    "failed to allocate reason strings");
		ret = -1;
		goto clean;
	}

	if (state == DHCP6S_EXIT) {
		goto launch;
	}

	RENDER_LIST(dns, "new_domain_name_servers", 1);
	RENDER_LIST(dnsname, "new_domain_name", 0);
	RENDER_LIST(ntp, "new_ntp_servers", 1);
	RENDER_LIST(sip, "new_sip_servers", 1);
	RENDER_LIST(sipname, "new_sip_name", 0);
	RENDER_LIST(nis, "new_nis_servers", 1);
	RENDER_LIST(nisname, "new_nis_name", 0);
	RENDER_LIST(nisp, "new_nisp_servers", 1);
	RENDER_LIST(nispname, "new_nisp_name", 0);
	RENDER_LIST(bcmcs, "new_bcmcs_servers", 1);
	RENDER_LIST(bcmcsname, "new_bcmcs_name", 0);
	RENDER_LIST(aftrname, "new_aftr_name", 0);

	if (prefixes) {
#define PDINFO_MAX	64
		char *str = "PDINFO";
		char *sptr;
		int slen = sizeof (str) + PDINFO_MAX * prefixes + 1;

		if ((sptr = envp[i++] = malloc(slen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate prefixinfo strings");
			ret = -1;
			goto clean;
		}

		memset(sptr, 0, slen);
		snprintf(sptr, slen, "%s=", str);

		for (iav = TAILQ_FIRST(&optinfo->iapd_list); iav;
		    iav = TAILQ_NEXT(iav, link)) {
			for (siav = TAILQ_FIRST(&iav->sublist); siav;
			    siav = TAILQ_NEXT(siav, link)) {
				if (siav->type == DHCP6_LISTVAL_PREFIX6) {
					char prefixinfo[PDINFO_MAX];

					snprintf(prefixinfo, sizeof(prefixinfo),
					    "%s/%d", in6addr2str(&siav->val_prefix6.addr, 0),
					    siav->val_prefix6.plen);

					strlcat(sptr, prefixinfo, slen);
					strlcat(sptr, " ", slen);
				}
			}
		}
	}

	for (rawopt = TAILQ_FIRST(&optinfo->rawopt_list); rawopt;
	    rawopt = TAILQ_NEXT(rawopt, link)) {
		/*
		 * max of 5 numbers after last underscore
		 * (seems like max DHCPv6 option could be 65535)
		 * then underscore and equal sign plus hex signs
		 * of each byte
		 */
		int slen = sizeof(raw_dhcp_option_str) + 5 + 2 +
		    rawopt->datalen * 2;
		char *sptr;

		if ((sptr = envp[i++] = malloc(slen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate string for DHCPv6 option %d",
			    rawopt->opnum);
			ret = -1;
			goto clean;
		}

		/* make raw options available as raw_dhcp_option_xyz=hexresponse */
		snprintf(sptr, slen, "%s_%d=", raw_dhcp_option_str, rawopt->opnum);
		const char *hex = "0123456789abcdef";
		char val[3];
		for (int o = 0; o < rawopt->datalen; o++) {
			val[0] = hex[(rawopt->data[o]>>4) & 0x0F];
			val[1] = hex[(rawopt->data[o]   ) & 0x0F];
			val[2] = 0x00;
			strlcat(sptr, val, slen);
		}
	}

launch:
	/* launch the script */
	pid = fork();
	if (pid < 0) {
		d_printf(LOG_ERR, FNAME, "failed to fork: %s", strerror(errno));
		ret = -1;
		goto clean;
	} else if (pid) {
		int wstatus;

		do {
			wpid = wait(&wstatus);
		} while (wpid != pid && wpid > 0);

		if (wpid < 0)
			d_printf(LOG_ERR, FNAME, "wait: %s", strerror(errno));
		else {
			d_printf(LOG_DEBUG, FNAME,
			    "script \"%s\" terminated", scriptpath);
		}
	} else {
		char *argv[2];
		int fd;

		argv[0] = scriptpath;
		argv[1] = NULL;

		if (safefile(scriptpath)) {
			d_printf(LOG_ERR, FNAME,
			    "script \"%s\" cannot be executed safely",
			    scriptpath);
			exit(1);
		}

		if (foreground == 0 && (fd = open("/dev/null", O_RDWR)) != -1) {
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			if (fd > STDERR_FILENO)
				close(fd);
		}

		execve(scriptpath, argv, envp);

		d_printf(LOG_ERR, FNAME, "child: exec failed: %s",
		    strerror(errno));
		exit(0);
	}

  clean:
	for (i = 0; i < envc; i++)
		free(envp[i]);
	free(envp);

	return ret;
}
