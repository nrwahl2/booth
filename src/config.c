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

#include "attr.h"
#include "booth.h"
#include "config.h"
#include "raft.h"
#include "ticket.h"
#include "log.h"

struct parser_context {
    const char *key;
    const char *value;
    struct ticket_config *ticket;
    int min_timeout;
    gchar *error;
};

struct parser_fn_info {
    const char *key;
    bool (*fn)(struct booth_config *, struct parser_context *);

    //! Option requires that a previous option has already set current ticket
    bool requires_ticket;
};

static void
free_attr_prereq(struct attr_prereq *prereq)
{
    if (prereq == NULL) {
        return;
    }
    g_free(prereq->attr_name);
    g_free(prereq->attr_val);
    g_free(prereq);
}

static void
free_ticket_config(struct ticket_config *ticket)
{
    if (ticket == NULL) {
        return;
    }

    g_free(ticket->clu_test.path);
    g_strfreev(ticket->clu_test.argv);

    if (ticket->attr != NULL) {
        g_hash_table_destroy(ticket->attr);
    }

    g_list_free_full(ticket->attr_prereqs, (GDestroyNotify) free_attr_prereq);
    free(ticket);
}

void
free_booth_config(struct booth_config *conf)
{
    if (conf == NULL) {
        return;
    }
    g_free(conf->site_user);
    g_free(conf->site_group);
    g_free(conf->arb_user);
    g_free(conf->arb_group);
    g_slist_free_full(conf->tickets, (GDestroyNotify) free_ticket_config);
    free(conf);
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
add_site(struct booth_config *conf, const char *addr_string, int type)
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

/* scan val for time; time is [0-9]+(ms)?, i.e. either in seconds
 * or milliseconds
 * returns -1 on failure, otherwise time in ms
 */
static long
read_time(const char *val)
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

extern int poll_timeout;

static bool
parse_transport(struct booth_config *conf, struct parser_context *context)
{
    if (strcasecmp(context->value, "UDP") != 0) {
        context->error = g_strdup_printf("Invalid transport protocol \"%s\"",
                                         context->value);
        return false;
    }

    return true;
}

static bool
parse_port(struct booth_config *conf, struct parser_context *context)
{
    // @FIXME Use strtol() and error-check
    conf->port = atoi(context->value);
    return true;
}

static bool
parse_name(struct booth_config *conf, struct parser_context *context)
{
    safe_copy(conf->name, context->value, BOOTH_NAME_LEN, context->key);
    return true;
}

#if (HAVE_LIBGNUTLS || HAVE_LIBGCRYPT || HAVE_LIBMHASH)
static bool
parse_authfile(struct booth_config *conf, struct parser_context *context)
{
    safe_copy(conf->authfile, context->value, BOOTH_PATH_LEN, context->key);
    return true;
}

static bool
parse_maxtimeskew(struct booth_config *conf, struct parser_context *context)
{
    // @FIXME Use strtol() and error-check
    conf->maxtimeskew = atoi(context->value);
    return true;
}
#endif  // (HAVE_LIBGNUTLS || HAVE_LIBGCRYPT || HAVE_LIBMHASH)

static bool
parse_site(struct booth_config *conf, struct parser_context *context)
{
    return add_site(conf, context->value, SITE);
}

static bool
parse_arbitrator(struct booth_config *conf, struct parser_context *context)
{
    return add_site(conf, context->value, ARBITRATOR);
}

static bool
parse_site_user(struct booth_config *conf, struct parser_context *context)
{
    g_free(conf->site_user);
    conf->site_user = g_strdup(context->value);
    return true;
}

static bool
parse_site_group(struct booth_config *conf, struct parser_context *context)
{
    g_free(conf->site_group);
    conf->site_group = g_strdup(context->value);
    return true;
}

static bool
parse_arbitrator_user(struct booth_config *conf, struct parser_context *context)
{
    g_free(conf->arb_user);
    conf->arb_user = g_strdup(context->value);
    return true;
}

static bool
parse_arbitrator_group(struct booth_config *conf,
                       struct parser_context *context)
{
    g_free(conf->arb_group);
    conf->arb_group = g_strdup(context->value);
    return true;
}

static bool
parse_debug(struct booth_config *conf, struct parser_context *context)
{
    if ((cl.type != CLIENT) && (cl.type != GEOSTORE)) {
        // @FIXME Use strtol() and error-check
        debug_level = max(debug_level, atoi(context->value));
    }

    return true;
}

static bool
parse_ticket(struct booth_config *conf, struct parser_context *context)
{
    static struct ticket_config defaults = {
        .clu_test = {
            .path = NULL,
            .pid = 0,
            .status = 0,
            .progstate = EXTPROG_IDLE,
        },
        .term_duration = DEFAULT_TICKET_EXPIRY,
        .timeout = DEFAULT_TICKET_TIMEOUT,
        .retries = DEFAULT_RETRIES,
        .acquire_after = 0,
        .mode = TICKET_MODE_AUTO,
    };

    if ((context->ticket != NULL)
        && (strcmp(context->ticket->name, "__defaults__") != 0)
        && !postproc_ticket(context->ticket)) {

        return false;
    }

    if (strcmp(context->value, "__defaults__") == 0) {
        context->ticket = &defaults;
        return true;
    }

    if (add_ticket(conf, context->value, &context->ticket, &defaults)) {
        return false;
    }

    return true;
}

static bool
parse_expire(struct booth_config *conf, struct parser_context *context)
{
    context->ticket->term_duration = read_time(context->value);

    if (context->ticket->term_duration <= 0) {
        context->error = g_strdup_printf("Expected time > 0 for %s",
                                         context->key);
        return false;
    }

    return true;
}

static bool
parse_timeout(struct booth_config *conf, struct parser_context *context)
{
    context->ticket->timeout = read_time(context->value);

    if (context->ticket->timeout <= 0) {
        context->error = g_strdup_printf("Expected time > 0 for %s",
                                         context->key);
        return false;
    }

    if (context->min_timeout == 0) {
        context->min_timeout = context->ticket->timeout;

    } else {
        context->min_timeout = min(context->min_timeout,
                                   context->ticket->timeout);
    }

    return true;
}

static bool
parse_retries(struct booth_config *conf, struct parser_context *context)
{
    char *end = NULL;

    errno = 0;
    context->ticket->retries = strtol(context->value, &end, 0);

    if ((errno != 0)
        || (*end != '\0') || (end == context->value)
        || (context->ticket->retries < 3) || (context->ticket->retries > 100)) {

        context->error = g_strdup_printf("Expected plain integer value in the "
                                         "range [3, 1000] for %s",
                                         context->key);
        return false;
    }

    return true;
}

static bool
parse_renewal_freq(struct booth_config *conf, struct parser_context *context)
{
    context->ticket->renewal_freq = read_time(context->value);

    if (context->ticket->renewal_freq <= 0) {
        context->error = g_strdup_printf("Expected time > 0 for %s",
                                         context->key);
        return false;
    }

    return true;
}

static bool
parse_acquire_after(struct booth_config *conf, struct parser_context *context)
{
    context->ticket->acquire_after = read_time(context->value);

    if (context->ticket->acquire_after < 0) {
        context->error = g_strdup_printf("Expected time >= 0 for %s",
                                         context->key);
        return false;
    }

    return true;
}

static bool
parse_before_acquire_handler(struct booth_config *conf,
                             struct parser_context *context)
{
    // Make arguments for execv()

    g_clear_pointer(&context->ticket->clu_test.path, g_free);
    g_clear_pointer(&context->ticket->clu_test.argv, g_strfreev);

    // The caller ensured context->value is non-empty
    if (!g_shell_parse_argv(context->value, NULL,
                            &context->ticket->clu_test.argv, NULL)) {
        context->error = g_strdup_printf("Failed to set %s: couldn't parse "
                                         "\"%s\" as command line or directory",
                                         context->key, context->value);
        return false;
    }

    context->ticket->clu_test.path =
        g_strdup(context->ticket->clu_test.argv[0]);
    return true;
}

static grant_type_e
parse_grant_type(const char *grant_type)
{
    if (strcmp(grant_type, "auto") == 0) {
        return GRANT_AUTO;
    }
    if (strcmp(grant_type, "manual") == 0) {
        return GRANT_MANUAL;
    }
    return 0;
}

static attr_op_e
parse_attr_op(const char *attr_op)
{
    if (strcmp(attr_op, "eq") == 0) {
        return ATTR_OP_EQ;
    }
    if (strcmp(attr_op, "ne") == 0) {
        return ATTR_OP_NE;
    }
    return 0;
}

static bool
parse_attr_prereq(struct booth_config *conf, struct parser_context *context)
{
    // Free using free_attr_prereq()
    struct attr_prereq *prereq = NULL;
    gint argc = 0;
    gchar **argv = NULL;
    bool rc = false;

    if (!g_shell_parse_argv(context->value, &argc, &argv, NULL)
        || (argc != 4)) {

        context->error = g_strdup_printf("Failed to parse %s from \"%s\". "
                                         "Usage: %s = grant_type name op value",
                                         context->key, context->value,
                                         context->key);
        goto done;
    }

    prereq = g_new(struct attr_prereq, 1);

    prereq->grant_type = parse_grant_type(argv[0]);
    if (prereq->grant_type == 0) {
        context->error = g_strdup_printf("%s is not a grant type", argv[0]);
        goto done;
    }

    prereq->attr_name = g_strdup(argv[1]);

    prereq->op = parse_attr_op(argv[2]);
    if (prereq->op == 0) {
        context->error = g_strdup_printf("%s is not an attribute operation", argv[2]);
        goto done;
    }

    prereq->attr_val = g_strdup(argv[3]);

    context->ticket->attr_prereqs = g_list_append(context->ticket->attr_prereqs,
                                                  prereq);
    rc = true;

done:
    if (!rc) {
        free_attr_prereq(prereq);
    }
    g_strfreev(argv);
    return rc;
}

static bool
parse_mode(struct booth_config *conf, struct parser_context *context)
{
    if (strcasecmp(context->value, "manual") == 0) {
        context->ticket->mode = TICKET_MODE_MANUAL;

    } else {
        /* @COMPAT Be more strict and throw an error on unrecognized values?
         * Anything other than "manual" is parsed to "auto".
         */
        context->ticket->mode = TICKET_MODE_AUTO;
    }

    return true;
}

static bool
parse_weights(struct booth_config *conf, struct parser_context *context)
{
    /* @COMPAT We need to treat a weights parameter as valid. However, it
     * doesn't do anything. Remove support in a future release.
     */
    return true;
}

static const struct parser_fn_info *
get_parser_fn_info(const char *key)
{
    static const struct parser_fn_info infos[] = {
        { "acquire-after", parse_acquire_after, true },
        { "arbitrator", parse_arbitrator, false },
        { "arbitrator-group", parse_arbitrator_group, false },
        { "arbitrator-user", parse_arbitrator_user, false },
        { "attr-prereq", parse_attr_prereq, true },
        { "before-acquire-handler", parse_before_acquire_handler, true },
        { "debug", parse_debug, false },
        { "expire", parse_expire, true },
        { "mode", parse_mode, true },
        { "name", parse_name, false },
        { "port", parse_port, false },
        { "renewal-freq", parse_renewal_freq, true },
        { "retries", parse_retries, true },
        { "site", parse_site, false },
        { "site-group", parse_site_group, false },
        { "site-user", parse_site_user, false },
        { "ticket", parse_ticket, false },
        { "timeout", parse_timeout, true },
        { "weights", parse_weights, true },

#if (HAVE_LIBGNUTLS || HAVE_LIBGCRYPT || HAVE_LIBMHASH)
        { "authfile", parse_authfile, false },
        { "maxtimeskew", parse_maxtimeskew, false },
#endif  // (HAVE_LIBGNUTLS || HAVE_LIBGCRYPT || HAVE_LIBMHASH)

        // @COMPAT Deprecated since 1.3
        { "transport", parse_transport, false },

        { NULL, },
    };

    for (const struct parser_fn_info *info = infos; info->key != NULL; info++) {
        if (strcmp(key, info->key) == 0) {
            return info;
        }
    }

    return NULL;
}

int
booth__read_config(struct booth_config **conf, const char *path)
{
    char line[1024] = { 0, };
    FILE *fp = NULL;
    int lineno = 0;
    struct parser_context context = { NULL, };
    const struct parser_fn_info *fn_info = NULL;

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
    (*conf)->site_user = g_strdup("hacluster");
    (*conf)->site_group = g_strdup("haclient");
    (*conf)->arb_user = g_strdup("nobody");
    (*conf)->arb_group = g_strdup("nobody");

    log_debug("reading config file %s", path);
    while (fgets(line, sizeof(line), fp)) {
        char *s = NULL;
        const char *key = NULL;
        const char *val = NULL;
        char *end_of_key = NULL;

        lineno++;

        s = g_strchomp(line);
        if ((*s == '\0') || (*s == '#')) {
            continue;
        }

        key = s;

        for (; isalnum(*s) || (*s == '-') || (*s == '_'); s++);

        end_of_key = s;
        if (end_of_key == key) {
            context.error = g_strdup("No key");
            goto err;
        }

        if (*end_of_key == '\0') {
            context.error = g_strdup("Expected '=' after key");
            goto err;
        }

        // Whitespace, and something else but nothing more?
        s = g_strchug(end_of_key);

        if (*s != '=') {
            context.error = g_strdup("Expected '=' after key");
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
                    context.error = g_strdup("Unterminated quoted string");
                    goto err;
                }

                // Remove and skip quote
                *s = 0;
                s++;
                g_strchug(s);
                if ((*s != '\0') && (*s != '#')) {
                    context.error = g_strdup("Surplus data after value");
                    goto err;
                }

                *s = 0;
                break;

            case 0:
                context.error = g_strdup("No value");
                goto err;

            default:
                val = s;
                break;
        }

        if (*val == '\0') {
            context.error = g_strdup("No value");
            goto err;
        }

        if ((strlen(key) > BOOTH_NAME_LEN) || (strlen(val) > BOOTH_NAME_LEN)) {
            context.error = g_strdup("key/value too long");
            goto err;
        }

        context.key = key;
        context.value = val;

        fn_info = get_parser_fn_info(context.key);
        if (fn_info == NULL) {
            context.error = g_strdup_printf("Unknown keyword \"%s\"",
                                            context.key);
            goto err;
        }

        if (fn_info->requires_ticket && (context.ticket == NULL)) {
            context.error = g_strdup_printf("Option %s can occur only below a "
                                            "ticket option", context.key);
            goto err;
        }

        if (!fn_info->fn(*conf, &context)) {
            goto err;
        }
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

    if (!postproc_ticket(context.ticket)) {
        goto out;
    }

    poll_timeout = min(POLL_TIMEOUT, context.min_timeout / 10);
    if (poll_timeout == 0) {
        poll_timeout = POLL_TIMEOUT;
    }

    return 0;

err:
    fclose(fp);

out:
    log_error("%s in config file line %d",
              ((context.error != NULL)? context.error : "Error"), lineno);
    g_free(context.error);

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
