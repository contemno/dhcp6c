/*	$KAME: dhcp6c_script.c,v 1.11 2004/11/28 10:48:38 jinmei Exp $	*/

/*
 * Copyright (C) 2003 WIDE Project.
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

static char sipserver_str[] = "new_sip_servers";
static char sipname_str[] = "new_sip_name";
static char dnsserver_str[] = "new_domain_name_servers";
static char dnsname_str[] = "new_domain_name";
static char ntpserver_str[] = "new_ntp_servers";
static char nisserver_str[] = "new_nis_servers";
static char nisname_str[] = "new_nis_name";
static char nispserver_str[] = "new_nisp_servers";
static char nispname_str[] = "new_nisp_name";
static char bcmcsserver_str[] = "new_bcmcs_servers";
static char bcmcsname_str[] = "new_bcmcs_name";
static char aftrname_str[] = "new_aftr_name";
static char raw_dhcp_option_str[] = "raw_dhcp_option";

#define DECLARE_LIST(lname)	int lname##_len = 0;

# define COUNT_LIST(lname)	do { \
	lname##_len = 0; \
	for (v = TAILQ_FIRST(&optinfo->lname##_list); v; \
	    v = TAILQ_NEXT(v, link)) \
		lname##_len++; \
	envc += lname##_len ? 1 : 0; \
} while (0)

int client6_script(char *, int, struct dhcp6_optinfo *);

int
client6_script(char *scriptpath, int state, struct dhcp6_optinfo *optinfo)
{
	int i, elen, ret = 0;
	int envc = 2;	/* we at least include the reason and the terminator */
	int prefixes = 0;
	char **envp, *s;
	char reason[32];
	char prefixinfo[32] = "\0";
	struct dhcp6_listval *v;
	struct dhcp6_event ev;
	struct rawoption *rawop;
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
	if (scriptpath == NULL || strlen(scriptpath) == 0)
		return -1;
	d_printf(LOG_DEBUG, FNAME, "executes %s", scriptpath);

	ev.state = state;

	if (state == DHCP6S_EXIT)
		goto setenv;

	COUNT_LIST(dns);
	COUNT_LIST(dnsname);
	COUNT_LIST(ntp);
	COUNT_LIST(sip);
	COUNT_LIST(sipname);
	COUNT_LIST(nis);
	COUNT_LIST(nisname);
	COUNT_LIST(nisp);
	COUNT_LIST(nispname);
	COUNT_LIST(bcmcs);
	COUNT_LIST(bcmcsname);
	COUNT_LIST(aftrname);

	/* XXX count rawopt_list here too? */

	for (iav = TAILQ_FIRST(&optinfo->iapd_list); iav; iav = TAILQ_NEXT(iav, link)) {
		for (siav = TAILQ_FIRST(&iav->sublist); siav; siav = TAILQ_NEXT(siav, link)) {
			if (siav->type == DHCP6_LISTVAL_PREFIX6) {
				prefixes += 1;
			}
		}
	}
	envc += prefixes ? 1 : 0;

setenv:
	/* allocate an environments array */
	if ((envp = malloc(sizeof (char *) * envc)) == NULL) {
		d_printf(LOG_NOTICE, FNAME,
		    "failed to allocate environment buffer");
		return -1;
	}
	memset(envp, 0, sizeof (char *) * envc);

	/*
	 * Copy the parameters as environment variables
	 */
	snprintf(reason, sizeof(reason), "REASON=%s",
	    dhcp6_event_statestr(&ev));
	i = 0;
	/* reason */
	if ((envp[i++] = strdup(reason)) == NULL) {
		d_printf(LOG_NOTICE, FNAME,
		    "failed to allocate reason strings");
		ret = -1;
		goto clean;
	}
	if (state == DHCP6S_EXIT)
		goto launch;

	/* "var=addr1 addr2 ... addrN" + null char for termination */
	if (dns_len) {
		elen = sizeof(dnsserver_str) +
		    (INET6_ADDRSTRLEN + 1) * dns_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for DNS servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", dnsserver_str);
		for (v = TAILQ_FIRST(&optinfo->dns_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}

	if (ntp_len) {
		elen = sizeof (ntpserver_str) +
		    (INET6_ADDRSTRLEN + 1) * ntp_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for NTP servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", ntpserver_str);
		for (v = TAILQ_FIRST(&optinfo->ntp_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}

	if (dnsname_len) {
		elen = sizeof(dnsname_str) + dnsname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for DNS name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", dnsname_str);
		for (v = TAILQ_FIRST(&optinfo->dnsname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}

	if (sip_len) {
		elen = sizeof(sipserver_str) +
		    (INET6_ADDRSTRLEN + 1) * sip_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for SIP servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", sipserver_str);
		for (v = TAILQ_FIRST(&optinfo->sip_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}

	if (sipname_len) {
		elen = sizeof(sipname_str) + sipname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for SIP domain name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", sipname_str);
		for (v = TAILQ_FIRST(&optinfo->sipname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}

	if (nis_len) {
		elen = sizeof(nisserver_str) +
		    (INET6_ADDRSTRLEN + 1) * nis_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for NIS servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", nisserver_str);
		for (v = TAILQ_FIRST(&optinfo->nis_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}

	if (nisname_len) {
		elen = sizeof (nisname_str) + nisname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for NIS domain name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", nisname_str);
		for (v = TAILQ_FIRST(&optinfo->nisname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}

	if (nisp_len) {
		elen = sizeof(nispserver_str) +
		    (INET6_ADDRSTRLEN + 1) * nisp_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for NIS+ servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", nispserver_str);
		for (v = TAILQ_FIRST(&optinfo->nisp_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}
	if (nispname_len) {
		elen = sizeof(nispname_str) + nispname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for NIS+ domain name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", nispname_str);
		for (v = TAILQ_FIRST(&optinfo->nispname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}

	if (bcmcs_len) {
		elen = sizeof(bcmcsserver_str) +
		    (INET6_ADDRSTRLEN + 1) * bcmcs_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for BCMC servers");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", bcmcsserver_str);
		for (v = TAILQ_FIRST(&optinfo->bcmcs_list); v;
		    v = TAILQ_NEXT(v, link)) {
			char *addr;

			addr = in6addr2str(&v->val_addr6, 0);
			strlcat(s, addr, elen);
			strlcat(s, " ", elen);
		}
	}
	if (bcmcsname_len) {
		elen = sizeof(bcmcsname_str) + bcmcsname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for BCMC domain name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", bcmcsname_str);
		for (v = TAILQ_FIRST(&optinfo->bcmcsname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}
	if (aftrname_len) {
		elen = sizeof(aftrname_str) + aftrname_len + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate strings for AFTR-Name");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", aftrname_str);
		for (v = TAILQ_FIRST(&optinfo->aftrname_list); v;
		    v = TAILQ_NEXT(v, link)) {
			strlcat(s, v->val_vbuf.dv_buf, elen);
			strlcat(s, " ", elen);
		}
	}

	if (prefixes) {
#define PDINFO_MAX	64
		char *str = "PDINFO";
		elen = sizeof (str) + PDINFO_MAX * prefixes + 1;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate prefixinfo strings");
			ret = -1;
			goto clean;
		}
		memset(s, 0, elen);
		snprintf(s, elen, "%s=", str);
		for (iav = TAILQ_FIRST(&optinfo->iapd_list); iav; iav = TAILQ_NEXT(iav, link)) {
			for (siav = TAILQ_FIRST(&iav->sublist); siav; siav = TAILQ_NEXT(siav, link)) {
				if (siav->type == DHCP6_LISTVAL_PREFIX6) {
					char prefixinfo[PDINFO_MAX];

					snprintf(prefixinfo, sizeof(prefixinfo),
					    "%s/%d", in6addr2str(&siav->val_prefix6.addr, 0),
					    siav->val_prefix6.plen);

					strlcat(s, prefixinfo, elen);
					strlcat(s, " ", elen);
				}
			}
		}
	}

	/* XXX */
	for (rawop = TAILQ_FIRST(&optinfo->rawopt_list); rawop; rawop = TAILQ_NEXT(rawop, link)) {
		// max of 5 numbers after last underscore (seems like max DHCPv6 option could be 65535)
		elen = sizeof(raw_dhcp_option_str) + 1 /* underscore */ + 1 /* equals sign */ + 5;
		elen += rawop->datalen * 2;
		if ((s = envp[i++] = malloc(elen)) == NULL) {
			d_printf(LOG_NOTICE, FNAME,
			    "failed to allocate string for DHCPv6 option %d",
			    rawop->opnum);
			ret = -1;
			goto clean;
		}

		// make raw options available as raw_dhcp_option_xyz=hexresponse
		snprintf(s, elen, "%s_%d=", raw_dhcp_option_str, rawop->opnum);
		const char * hex = "0123456789abcdef";
		char * val = (char*)malloc(3);
		for (int o = 0; o < rawop->datalen; o++) {
			val[0] = hex[(rawop->data[o]>>4) & 0x0F];
			val[1] = hex[(rawop->data[o]   ) & 0x0F];
			val[2] = 0x00;
			strlcat(s, val, elen);
		}
		free(val);
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
