/* 
 * Copyright (C) 2011 Jiaju Zhang <jjzhang@suse.de>
 * Copyright (C) 2013-2014 Philipp Marek <philipp.marek@linbit.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "b_config.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <zlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>

#include <glib.h>	    // g_*

#include "booth.h"
#include "config.h"
#include "raft.h"
#include "ticket.h"
#include "log.h"

// @TODO Make these no longer file-scope
static struct ticket_config defaults = { { 0 } };
static int min_timeout = 0;

void
free_booth_config(struct booth_config *conf)
{
    if (conf != NULL) {
        g_slist_free_full(conf->tickets, free);
        free(conf);
    }
}

static void
hostname_to_ip(char *hostname)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int res;
	int addr_found = 0;
	const char *ntop_res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	res = getaddrinfo(hostname, NULL, &hints, &result);

	if (res != 0) {
		log_error("can't find IP for the host \"%s\"", hostname);
		return;
	}

	/* Return the first found AF_INET or AF_INET6 address */
	for (rp = result; rp && !addr_found; rp = rp->ai_next) {
		if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6) {
			continue ;
		}

		switch (rp->ai_family) {
		case AF_INET:
			ntop_res = inet_ntop(rp->ai_family,
			    &((struct sockaddr_in *)(rp->ai_addr))->sin_addr,
			    hostname, BOOTH_NAME_LEN - 1);
			break;
		case AF_INET6:
			ntop_res = inet_ntop(rp->ai_family,
			    &((struct sockaddr_in6 *)(rp->ai_addr))->sin6_addr,
			    hostname, BOOTH_NAME_LEN - 1);
			break;
		}

		if (ntop_res) {
			/* buffer overflow will not happen (IPv6 notation < 63 chars),
			   but suppress the warnings */
			hostname[BOOTH_NAME_LEN - 1] = '\0';
			addr_found = 1;
		}
	}

	if (!addr_found) {
		log_error("no IP addresses found for the host \"%s\"", hostname);
	}

	freeaddrinfo(result);
}

static int
add_site(struct booth_config *conf, char *addr_string, int type)
{
	int rv = 0;
	struct booth_site *site;
	uLong nid;
	uint32_t mask;
	int i;

	assert(conf != NULL);

	if (conf->site_count == MAX_NODES) {
		log_error("too many nodes");
		return 1;
	}
	if (strnlen(addr_string, sizeof(conf->sites[0].addr_string))
			>= sizeof(conf->sites[0].addr_string)) {
		log_error("site address \"%s\" too long", addr_string);
		return 1;
	}

	site = &conf->sites[conf->site_count];
	site->family = AF_INET;
	site->type = type;

	/* buffer overflow will not hapen (we've already checked that
	   addr_string will fit incl. terminating '\0' above), but
	   suppress the warnings with copying everything but the boundary
	   byte, which is valid as-is, since this last byte will be safely
	   pre-zeroed from the struct booth_config initialization */
	strncpy(site->addr_string, addr_string, sizeof(site->addr_string) - 1);

	if (!(inet_pton(AF_INET, site->addr_string, &site->sa4.sin_addr) > 0) &&
        !(inet_pton(AF_INET6, site->addr_string, &site->sa6.sin6_addr) > 0)) {

		/* Not a valid address, so let us try to convert it into an IP address */
		hostname_to_ip(site->addr_string);
	}

	site->index = conf->site_count;
	site->bitmask = 1 << conf->site_count;
	/* Catch site overflow */
	assert(site->bitmask);
	conf->all_bits |= site->bitmask;
	if (type == SITE) {
		conf->sites_bits |= site->bitmask;
	}

	site->tcp_fd = -1;

	conf->site_count++;

	memset(&site->sa6, 0, sizeof(site->sa6));

	nid = crc32(0L, NULL, 0);
	/* Using the ASCII representation in site->addr_string (both sizeof()
	 * and strlen()) gives quite a lot of collisions; a brute-force run
	 * from 0.0.0.0 to 24.0.0.0 gives ~4% collisions, and this tends to
	 * increase even more.
	 * Whether there'll be a collision in real-life, with 3 or 5 nodes, is
	 * another question ... but for now get the ID from the binary
	 * representation - that had *no* collisions up to 32.0.0.0.
	 * Note that POSIX mandates inet_pton to arange the address pointed
	 * to by "dst" in network byte order, assuring little/big-endianess
	 * mutual compatibility. */
	if (inet_pton(AF_INET,
				site->addr_string,
				&site->sa4.sin_addr) > 0) {

		site->family = AF_INET;
		site->sa4.sin_family = site->family;
		site->sa4.sin_port = htons(conf->port);
		site->saddrlen = sizeof(site->sa4);
		site->addrlen = sizeof(site->sa4.sin_addr);
		site->site_id = crc32(nid, (void*)&site->sa4.sin_addr, site->addrlen);

	} else if (inet_pton(AF_INET6,
				site->addr_string,
				&site->sa6.sin6_addr) > 0) {

		site->family = AF_INET6;
		site->sa6.sin6_family = site->family;
		site->sa6.sin6_flowinfo = 0;
		site->sa6.sin6_port = htons(conf->port);
		site->saddrlen = sizeof(site->sa6);
		site->addrlen = sizeof(site->sa6.sin6_addr);
		site->site_id = crc32(nid, (void*)&site->sa6.sin6_addr, site->addrlen);

	} else {
		log_error("Address string \"%s\" is bad", site->addr_string);
		rv = EINVAL;
	}

	/* Make sure we will never collide with NO_ONE,
	 * or be negative (to get "get_local_id() < 0" working). */
	mask = 1 << (sizeof(site->site_id)*8 -1);
	assert(NO_ONE & mask);
	site->site_id &= ~mask;


	/* Test for collisions with other sites */
	for (i = 0; i < site->index; i++) {
		if (conf->sites[i].site_id == site->site_id) {
			log_error("Got a site-ID collision. Please file a bug on https://github.com/ClusterLabs/booth/issues/new, attaching the configuration file.");
			exit(1);
		}
	}

	return rv;
}

static int
add_ticket(struct booth_config *conf, const char *name,
           struct ticket_config **tkp, const struct ticket_config *def)
{
	const char *s = NULL;
	struct ticket_config *tk = NULL;

	assert(conf != NULL);

	if (!valid_ticket_name(name)) {
		log_error("ticket name \"%s\" too long.", name);
		return -EINVAL;
	}

	if (find_ticket_by_name(conf, name, NULL)) {
		log_error("ticket name \"%s\" used again.", name);
		return -EINVAL;
	}

	for (s = name; isalnum(*s) || (*s == '-') || (*s == '/'); s++);

	if (*s != '\0') {
		/* @TODO Should we advertise that ticket names can contain '-'
		 * and '/', or keep that a secret?
		 */
		log_error("ticket name \"%s\" invalid; only alphanumeric names.", name);
		return -EINVAL;
	}

	tk = calloc(1, sizeof(struct ticket_config));
	if (tk == NULL) {
		log_error("Failed to allocate new ticket %s");
		return -ENOMEM;
	}

	strcpy(tk->name, name);
	tk->timeout = def->timeout;
	tk->term_duration = def->term_duration;
	tk->retries = def->retries;
	memcpy(tk->weight, def->weight, sizeof(tk->weight));
	tk->mode = def->mode;

	conf->tickets = g_slist_append(conf->tickets, tk);

	if (tkp)
		*tkp = tk;

	return 0;
}

static int
postproc_ticket(struct ticket_config *tk)
{
	if (!tk)
		return 1;

	if (!tk->renewal_freq) {
		tk->renewal_freq = tk->term_duration/2;
	}

	if (tk->timeout*(tk->retries+1) >= tk->renewal_freq) {
		log_error("%s: total amount of time to "
			"retry sending packets cannot exceed "
			"renewal frequency "
			"(%d*(%d+1) >= %d)",
			tk->name, tk->timeout, tk->retries, tk->renewal_freq);
		return 0;
	}
	return 1;
}

/* returns number of weights, or -1 on bad input. */
static int
do_parse_weights(const char *input, int weights[MAX_NODES])
{
	int i, v;
	char *cp;

	for(i=0; i<MAX_NODES; i++) {
		/* End of input? */
		if (*input == 0)
			break;

		v = strtol(input, &cp, 0);
		if (input == cp) {
			log_error("No integer weight value at \"%s\"", input);
			return -1;
		}

		weights[i] = v;

		while (*cp) {
			/* Separator characters */
			if (isspace(*cp) ||
					strchr(",;:-+", *cp))
				cp++;
			/* Next weight */
			else if (isdigit(*cp))
				break;
			/* Rest */
			else {
				log_error("Invalid character at \"%s\"", cp);
				return -1;
			}
		}

		input = cp;
	}


	/* Fill rest of vector. */
	for(v=i; v<MAX_NODES; v++) {
		weights[v] = 0;
	}

	return i;
}

/* returns TICKET_MODE_AUTO if failed to parse the ticket mode. */
static ticket_mode_e
retrieve_ticket_mode(const char *input)
{
	if (strcasecmp(input, "manual") == 0) {
		return TICKET_MODE_MANUAL;
	}

	return TICKET_MODE_AUTO;
}

/* scan val for time; time is [0-9]+(ms)?, i.e. either in seconds
 * or milliseconds
 * returns -1 on failure, otherwise time in ms
 */
static long
read_time(char *val)
{
	long t;
	char *ep;

	t = strtol(val, &ep, 10);
	if (ep == val) { /* matched none */
		t = -1L;
	} else if (*ep == '\0') { /* matched all */
		t = t*1000L; /* in seconds, convert to ms */
	} else if (strcmp(ep, "ms")) { /* ms not exactly matched */
		t = -1L;
	} /* otherwise, time in ms */
	/* if second fractions configured, send finer resolution
	 * times (i.e. term_valid_for) */
	if (t % 1000L) {
		TIME_MULT = 1000;
	}
	return t;
}

/* make arguments for execv(2)
 * tk->clu_test.path points to the path
 * tk->clu_test.argv is argument vector (starts with the prog)
 * (strtok pokes holes in the configuration parameter value, i.e.
 * we don't need to allocate memory for arguments)
 */
static int
parse_extprog(char *val, struct ticket_config *tk)
{
	char *p;
	int i = 0;

	if (tk->clu_test.path) {
		free(tk->clu_test.path);
	}
	if (!(tk->clu_test.path = strdup(val))) {
		log_error("out of memory");
		return -1;
	}

	p = strtok(tk->clu_test.path, " \t");
	tk->clu_test.argv[i++] = p;
	do {
		p = strtok(NULL, " \t");
		if (i >= MAX_ARGS) {
			log_error("too many arguments for the acquire-handler");
			free(tk->clu_test.path);
			return -1;
		}
		tk->clu_test.argv[i++] = p;
	} while (p);

	return 0;
}

struct toktab grant_type[] = {
	{ "auto", GRANT_AUTO},
	{ "manual", GRANT_MANUAL},
	{ NULL, 0},
};

struct toktab attr_op[] = {
	{"eq", ATTR_OP_EQ},
	{"ne", ATTR_OP_NE},
	{NULL, 0},
};

static int
lookup_tokval(char *key, struct toktab *tab)
{
	struct toktab *tp;

	for (tp = tab; tp->str; tp++) {
		if (!strcmp(tp->str, key))
			return tp->val;
	}
	return 0;
}

/* attribute prerequisite
 */
static int
do_parse_attr_prereq(char *val, struct ticket_config *tk)
{
	struct attr_prereq *ap = NULL;
	char *p;

	ap = (struct attr_prereq *)calloc(1, sizeof(struct attr_prereq));
	if (!ap) {
		log_error("out of memory");
		return -1;
	}

	p = strtok(val, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	ap->grant_type = lookup_tokval(p, grant_type);
	if (!ap->grant_type) {
		log_error("%s is not a grant type", p);
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	if (!(ap->attr_name = strdup(p))) {
		log_error("out of memory");
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	ap->op = lookup_tokval(p, attr_op);
	if (!ap->op) {
		log_error("%s is not an attribute operation", p);
		goto err_out;
	}

	p = strtok(NULL, " \t");
	if (!p) {
		log_error("not enough arguments to attr-prereq");
		goto err_out;
	}
	if (!(ap->attr_val = strdup(p))) {
		log_error("out of memory");
		goto err_out;
	}

	tk->attr_prereqs = g_list_append(tk->attr_prereqs, ap);
	if (!tk->attr_prereqs) {
		log_error("out of memory");
		goto err_out;
	}

	return 0;

err_out:
	if (ap) {
		if (ap->attr_val)
			free(ap->attr_val);
		if (ap->attr_name)
			free(ap->attr_name);
		free(ap);
	}
	return -1;
}

extern int poll_timeout;

static bool
parse_transport(struct booth_config *conf, char *value, action_t action,
                struct ticket_config **ticket, gchar **error)
{
    if (strcasecmp(value, "UDP") != 0) {
        *error = g_strdup_printf("Invalid transport protocol \"%s\"", value);
        return false;
    }

    return true;
}

static bool
parse_port(struct booth_config *conf, char *value, action_t action,
           struct ticket_config **ticket, gchar **error)
{
    // @FIXME Use strtol() and error-check
    conf->port = atoi(value);
    return true;
}

static bool
parse_name(struct booth_config *conf, char *value, action_t action,
           struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->name, value, BOOTH_NAME_LEN, "name");
    return true;
}

static bool
parse_authfile(struct booth_config *conf, char *value, action_t action,
               struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->authfile, value, BOOTH_PATH_LEN, "authfile");
    return true;
}

static bool
parse_maxtimeskew(struct booth_config *conf, char *value, action_t action,
                  struct ticket_config **ticket, gchar **error)
{
    // @FIXME Use strtol() and error-check
    conf->maxtimeskew = atoi(value);
    return true;
}

static bool
parse_site(struct booth_config *conf, char *value, action_t action,
           struct ticket_config **ticket, gchar **error)
{
    return add_site(conf, value, SITE);
}

static bool
parse_arbitrator(struct booth_config *conf, char *value, action_t action,
                 struct ticket_config **ticket, gchar **error)
{
    return add_site(conf, value, ARBITRATOR);
}

static bool
parse_site_user(struct booth_config *conf, char *value, action_t action,
                struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->site_user, value, BOOTH_NAME_LEN, "site-user");
    return true;
}

static bool
parse_site_group(struct booth_config *conf, char *value, action_t action,
                 struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->site_group, value, BOOTH_NAME_LEN, "site-group");
    return true;
}

static bool
parse_arbitrator_user(struct booth_config *conf, char *value, action_t action,
                      struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->arb_user, value, BOOTH_NAME_LEN, "arbitrator-user");
    return true;
}

static bool
parse_arbitrator_group(struct booth_config *conf, char *value, action_t action,
                       struct ticket_config **ticket, gchar **error)
{
    safe_copy(conf->arb_group, value, BOOTH_NAME_LEN, "arbitrator-group");
    return true;
}

static bool
parse_debug(struct booth_config *conf, char *value, action_t action,
            struct ticket_config **ticket, gchar **error)
{
    if ((action != CLIENT) && (action != GEOSTORE)) {
        // @FIXME Use strtol() and error-check
        debug_level = max(debug_level, atoi(value));
    }

    return true;
}

static bool
parse_ticket(struct booth_config *conf, char *value, action_t action,
             struct ticket_config **ticket, gchar **error)
{
    if ((*ticket != NULL)
        && (strcmp((*ticket)->name, "__defaults__") != 0)
        && !postproc_ticket(*ticket)) {

        return false;
    }

    if (strcmp(value, "__defaults__") == 0) {
        *ticket = &defaults;
        return true;
    }

    if (add_ticket(conf, value, ticket, &defaults)) {
        return false;
    }

    return true;
}

static bool
parse_expire(struct booth_config *conf, char *value, action_t action,
             struct ticket_config **ticket, gchar **error)
{
    (*ticket)->term_duration = read_time(value);

    if ((*ticket)->term_duration <= 0) {
        *error = g_strdup("Expected time > 0 for expire");
        return false;
    }

    return true;
}

static bool
parse_timeout(struct booth_config *conf, char *value, action_t action,
              struct ticket_config **ticket, gchar **error)
{
    (*ticket)->timeout = read_time(value);

    if ((*ticket)->timeout <= 0) {
        *error = g_strdup("Expected time > 0 for timeout");
        return false;
    }

    if (min_timeout == 0) {
        min_timeout = (*ticket)->timeout;
    } else {
        min_timeout = min(min_timeout, (*ticket)->timeout);
    }

    return true;
}

static bool
parse_retries(struct booth_config *conf, char *value, action_t action,
              struct ticket_config **ticket, gchar **error)
{
    char *end = NULL;

    errno = 0;
    (*ticket)->retries = strtol(value, &end, 0);

    if ((errno != 0)
        || (*end != '\0') || (end == value)
        || ((*ticket)->retries < 3) || ((*ticket)->retries > 100)) {

        *error = g_strdup("Expected plain integer value in the range [3, 1000] "
                          "for retries");
        return false;
    }

    return true;
}

static bool
parse_renewal_freq(struct booth_config *conf, char *value, action_t action,
                   struct ticket_config **ticket, gchar **error)
{
    (*ticket)->renewal_freq = read_time(value);

    if ((*ticket)->renewal_freq <= 0) {
        *error = g_strdup("Expected time > 0 for renewal-freq");
        return false;
    }

    return true;
}

static bool
parse_acquire_after(struct booth_config *conf, char *value, action_t action,
                    struct ticket_config **ticket, gchar **error)
{
    (*ticket)->acquire_after = read_time(value);

    if ((*ticket)->acquire_after < 0) {
        *error = g_strdup("Expected time >= 0 for acquire-after");
        return false;
    }

    return true;
}

static bool
parse_before_acquire_handler(struct booth_config *conf, char *value,
                             action_t action, struct ticket_config **ticket,
                             gchar **error)
{
    // @TODO Pull parse_extprog() body into here and invert return code
    return !parse_extprog(value, *ticket);
}

static bool
parse_attr_prereq(struct booth_config *conf, char *value, action_t action,
                  struct ticket_config **ticket, gchar **error)
{
    // @TODO Pull do_parse_attr_prereq() body into here and invert return code
    return !do_parse_attr_prereq(value, *ticket);
}

static bool
parse_mode(struct booth_config *conf, char *value, action_t action,
           struct ticket_config **ticket, gchar **error)
{
    (*ticket)->mode = retrieve_ticket_mode(value);
    return true;
}

static bool
parse_weights(struct booth_config *conf, char *value, action_t action,
              struct ticket_config **ticket, gchar **error)
{
    return (do_parse_weights(value, (*ticket)->weight) >= 0);
}

int
booth__read_config(struct booth_config **conf, const char *path,
                   action_t action)
{
    char line[1024] = { 0, };
    FILE *fp = NULL;
    gchar *error = NULL;
    int lineno = 0;
    struct ticket_config *current_tk = NULL;

    assert(conf != NULL);
    free(*conf);

    fp = fopen(path, "r");
    if (!fp) {
        log_error("failed to open %s: %s", path, strerror(errno));
        *conf = NULL;
        return -1;
    }

    *conf = calloc(1, sizeof(struct booth_config));
    if (*conf == NULL) {
        fclose(fp);
        log_error("failed to alloc memory for booth config");
        return -ENOMEM;
    }

    booth__set_transport_fns(*conf);

    (*conf)->port = BOOTH_DEFAULT_PORT;
    (*conf)->maxtimeskew = BOOTH_DEFAULT_MAX_TIME_SKEW;
    (*conf)->authkey[0] = '\0';

    // Provide safe defaults. -1 is reserved, though.
    (*conf)->uid = -2;
    (*conf)->gid = -2;
    strcpy((*conf)->site_user,  "hacluster");
    strcpy((*conf)->site_group, "haclient");
    strcpy((*conf)->arb_user,   "nobody");
    strcpy((*conf)->arb_group,  "nobody");

    do_parse_weights("", defaults.weight);
    defaults.clu_test.path  = NULL;
    defaults.clu_test.pid  = 0;
    defaults.clu_test.status  = 0;
    defaults.clu_test.progstate  = EXTPROG_IDLE;
    defaults.term_duration        = DEFAULT_TICKET_EXPIRY;
    defaults.timeout       = DEFAULT_TICKET_TIMEOUT;
    defaults.retries       = DEFAULT_RETRIES;
    defaults.acquire_after = 0;
    defaults.mode          = TICKET_MODE_AUTO;

    log_debug("reading config file %s", path);
    while (fgets(line, sizeof(line), fp)) {
        int i = 0;
        char *s = NULL;
        char *key = NULL;
        char *val = NULL;
        char *end_of_key = NULL;

        lineno++;

        s = g_strchug(line);
        if ((*s == '\0') || (*s == '#')) {
            continue;
        }

        key = s;

        for (; isalnum(*s) || (*s == '-') || (*s == '_'); s++);

        end_of_key = s;
        if (end_of_key == key) {
            error = g_strdup("No key");
            goto err;
        }

        if (*end_of_key == '\0') {
            goto exp_equal;
        }

        // Whitespace, and something else but nothing more?
        s = g_strchug(end_of_key);

        if (*s != '=') {
exp_equal:
            error = g_strdup("Expected '=' after key");
            goto err;
        }
        s++;

        /* It's my buffer, and I terminate if I want to. But not earlier than
         * this, because we had to check for '='.
         */
        *end_of_key = 0;


        // Value tokenizing
        g_strchug(s);
        switch (*s) {
            case '"':
            case '\'':
                val = s+1;
                s = strchr(val, *s);

                if (s == NULL) {
                    error = g_strdup("Unterminated quoted string");
                    goto err;
                }

                // Remove and skip quote
                *s = 0;
                s++;
                g_strchug(s);
                if ((*s != '\0') && (*s != '#')) {
                    error = g_strdup("Surplus data after value");
                    goto err;
                }

                *s = 0;
                break;

            case 0:
no_value:
                error = g_strdup("No value");
                goto err;
                break;

            default:
                val = s;
                // Rest of line
                i = strlen(s);

                // i > 0 because of "case 0" above
                while ((i > 0) && isspace(s[i-1])) {
                    i--;
                }
                s += i;
                *s = 0;
        }

        if (val == s)
            goto no_value;


        if ((strlen(key) > BOOTH_NAME_LEN) || (strlen(val) > BOOTH_NAME_LEN)) {
            error = g_strdup("key/value too long");
            goto err;
        }

        // @COMPAT Deprecated since 1.3
        if (strcmp(key, "transport") == 0) {
            if (!parse_transport(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "port") == 0) {
            if (!parse_port(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "name") == 0) {
            if (!parse_name(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

#if HAVE_LIBGNUTLS || HAVE_LIBGCRYPT || HAVE_LIBMHASH
        if (strcmp(key, "authfile") == 0) {
            if (!parse_authfile(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "maxtimeskew") == 0) {
            if (!parse_maxtimeskew(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }
#endif

        if (strcmp(key, "site") == 0) {
            if (!parse_site(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "arbitrator") == 0) {
            if (!parse_arbitrator(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "site-user") == 0) {
            if (!parse_site_user(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "site-group") == 0) {
            if (!parse_site_group(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "arbitrator-user") == 0) {
            if (!parse_arbitrator_user(*conf, val, action, &current_tk,
                                       &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "arbitrator-group") == 0) {
            if (!parse_arbitrator_group(*conf, val, action, &current_tk,
                                        &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "debug") == 0) {
            if (!parse_debug(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "ticket") == 0) {
            if (!parse_ticket(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        /* current_tk must be allocated at this point. Otherwise, we don't know
         * to which ticket the key refers.
         */
        if (current_tk == NULL) {
            error = g_strdup_printf("Unexpected keyword \"%s\"", key);
            goto err;
        }

        if (strcmp(key, "expire") == 0) {
            if (!parse_expire(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "timeout") == 0) {
            if (!parse_timeout(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "retries") == 0) {
            if (!parse_retries(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "renewal-freq") == 0) {
            if (!parse_renewal_freq(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "acquire-after") == 0) {
            if (!parse_acquire_after(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "before-acquire-handler") == 0) {
            if (!parse_before_acquire_handler(*conf, val, action, &current_tk,
                                              &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "attr-prereq") == 0) {
            if (!parse_attr_prereq(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "mode") == 0) {
            if (!parse_mode(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        if (strcmp(key, "weights") == 0) {
            if (!parse_weights(*conf, val, action, &current_tk, &error)) {
                goto err;
            }
            continue;
        }

        error = g_strdup_printf("Unknown keyword \"%s\"", key);
        goto err;
    }
    fclose(fp);

    if (((*conf)->site_count % 2) == 0) {
        log_warn("Odd number of nodes is strongly recommended!");
    }

    // Default: make config name match config filename
    if (!(*conf)->name[0]) {
        char *cp = NULL;
        char *cp2 = NULL;

        cp = strrchr(path, '/');
        cp = cp ? cp+1 : (char *)path;
        cp2 = strrchr(cp, '.');
        if (!cp2) {
            cp2 = cp + strlen(cp);
        }

        if (cp2-cp >= BOOTH_NAME_LEN) {
            log_error("Booth config file name too long");
            goto out;
        }

        strncpy((*conf)->name, cp, cp2-cp);
        *((*conf)->name+(cp2-cp)) = '\0';
    }

    if (!postproc_ticket(current_tk)) {
        goto out;
    }

    poll_timeout = min(POLL_TIMEOUT, min_timeout/10);
    if (poll_timeout == 0) {
        poll_timeout = POLL_TIMEOUT;
    }

    return 0;

err:
    fclose(fp);

out:
    log_error("%s in config file line %d", ((error != NULL)? error : "Error"),
              lineno);
    g_free(error);

    g_clear_pointer(conf, free_booth_config);
    return -1;
}

int
check_config(struct booth_config *conf, int type)
{
	struct passwd *pw;
	struct group *gr;
	char *cp, *input;

	if (conf == NULL) {
		return -1;
	}

	input = (type == ARBITRATOR)
		? conf->arb_user
		: conf->site_user;
	if (!*input)
		goto u_inval;
	if (isdigit(input[0])) {
		conf->uid = strtol(input, &cp, 0);
		if (*cp != 0) {
u_inval:
			log_error("User \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	} else {
		pw = getpwnam(input);
		if (!pw)
			goto u_inval;
		conf->uid = pw->pw_uid;
	}


	input = (type == ARBITRATOR)
		? conf->arb_group
		: conf->site_group;

	if (!*input) {
		goto g_inval;
	}

	if (isdigit(input[0])) {
		conf->gid = strtol(input, &cp, 0);
		if (*cp != 0) {
g_inval:
			log_error("Group \"%s\" cannot be resolved into a UID.", input);
			return ENOENT;
		}
	} else {
		gr = getgrnam(input);
		if (!gr) {
			goto g_inval;
		}
		conf->gid = gr->gr_gid;
	}

	return 0;
}

static bool
get_if_other_site(const struct booth_site *site, void *user_data)
{
    struct booth_site **other_site = user_data;

    if ((site == local) || (site->type != SITE)) {
        // Continue looking for the non-local site in a two-site configuration
        return true;
    }

    if (*other_site != NULL) {
        /* *other_site was set during a previous iteration, so there are more
         * than two sites. OTHER_SITE is supported only in two-site
         * configurations.
         *
         * We can't rely on conf->site_count, because it includes sites with
         * type other than SITE.
         *
         * Return false to stop looking and indicate that there is no valid
         * OTHER_SITE.
         */
        return false;
    }

    // Cast away const for output argument
    *other_site = (struct booth_site *) site;

    /* Keep looking. If there is another non-local site, we will return false.
     * See comment above.
     */
    return true;
}

struct get_if_name_matches_data {
    const char *name;
    struct booth_site **match;
};

static bool
get_if_name_matches(const struct booth_site *site, void *user_data)
{
    struct get_if_name_matches_data *data = user_data;

    if ((site->type == SITE) && (strcmp(site->addr_string, data->name) == 0)) {
        // Cast away const for output argument
        *data->match = (struct booth_site *) site;
        return false;
    }

    // Continue looking for a match
    return true;
}

bool
find_site_by_name(const struct booth_config *conf, const char *name,
                  struct booth_site **node)
{
    struct get_if_name_matches_data data = {
        .name = name,
        .match = node,
    };

    assert((conf != NULL) && (name != NULL) && (node != NULL));

    if (strcmp(name, OTHER_SITE) == 0) {
        /* get_if_other_site() returns true if zero or one non-local site is
         * site is found. If it returns true and *node is set, then *node is
         * *node is OTHER_SITE. Otherwise, there is no valid OTHER_SITE.
         */
        return booth__foreach_const_site(conf, get_if_other_site, node)
               && (*node != NULL);
    }

    // get_if_name_matches() returns false if it found a match
    return !booth__foreach_const_site(conf, get_if_name_matches, &data);
}

struct get_if_id_matches_data {
    const uint32_t id;
    struct booth_site **match;
};

static bool
get_if_id_matches(const struct booth_site *site, void *user_data)
{
    struct get_if_id_matches_data *data = user_data;

    if (site->site_id == data->id) {
        // Cast away const for output argument
        *data->match = (struct booth_site *) site;
        return false;
    }

    // Continue looking for a match
    return true;
}

bool
find_site_by_id(const struct booth_config *conf, uint32_t id,
                struct booth_site **node)
{
    struct get_if_id_matches_data data = {
        .id = id,
        .match = node,
    };

    assert((conf != NULL) && (node != NULL));

    if (id == NO_ONE) {
        *node = no_leader;
        return true;
    }

    // get_if_id_matches() returns false if it found a match
    return !booth__foreach_const_site(conf, get_if_id_matches, &data);
}

const char *
type_to_string(int type)
{
	switch (type)
	{
		case ARBITRATOR: return "arbitrator";
		case SITE:       return "site";
		case CLIENT:     return "client";
		case GEOSTORE:   return "attr";
	}
	return "??invalid-type??";
}
