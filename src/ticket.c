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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>

#include <glib.h>		    // GSList

#ifndef RANGE2RANDOM_GLIB
#include <clplumbing/cl_random.h>
#else
#include "alt/range2random_glib.h"
#endif
#include "ticket.h"
#include "config.h"
#include "pacemaker.h"
#include "inline-fn.h"
#include "log.h"
#include "booth.h"
#include "raft.h"
#include "handler.h"
#include "request.h"
#include "manual.h"

extern int TIME_RES;

/*!
 * \internal
 * \brief Call a function for each configured site
 *
 * \param[in,out] conf       Booth configuration
 * \param[in]     fn         Function to call for each site in \p conf (returns
 *                           \c true to continue iterating over the rest of the
 *                           sites, or \c false to stop)
 * \param[in,out] user_data  User data to pass to \p fn
 *
 * \return \c false if any \p fn call returned \c false, or \c true otherwise
 */
bool
booth__foreach_site(struct booth_config *conf,
                    bool (*fn)(struct booth_site *, void *), void *user_data)
{
    for (int i = 0; i < conf->site_count; i++) {
        struct booth_site *site = &conf->sites[i];

        if (!fn(site, user_data)) {
            return false;
        }
    }
    return true;
}

/*!
 * \internal
 * \brief Call a function for each configured site, without modifying it
 *
 * \param[in]     conf       Booth configuration
 * \param[in]     fn         Function to call for each site in \p conf (returns
 *                           \c true to continue iterating over the rest of the
 *                           sites, or \c false to stop)
 * \param[in,out] user_data  User data to pass to \p fn
 *
 * \return \c false if any \p fn call returned \c false, or \c true otherwise
 */
bool
booth__foreach_const_site(const struct booth_config *conf,
                          bool (*fn)(const struct booth_site *, void *),
                          void *user_data)
{
    for (int i = 0; i < conf->site_count; i++) {
        const struct booth_site *site = &conf->sites[i];

        if (!fn(site, user_data)) {
            return false;
        }
    }
    return true;
}

/*!
 * \internal
 * \brief Call a function for each configured ticket
 *
 * \param[in,out] conf       Booth configuration
 * \param[in]     fn         Function to call for each ticket in \p conf
 *                           (returns \c true to continue iterating over the
 *                           rest of the tickets, or \c false to stop)
 * \param[in,out] user_data  User data to pass to \p fn
 *
 * \return \c false if any \p fn call returned \c false, or \c true otherwise
 */
bool
booth__foreach_ticket(struct booth_config *conf,
                      bool (*fn)(struct ticket_config *, void *),
                      void *user_data)
{
    for (GSList *iter = conf->tickets; iter != NULL; iter = iter->next) {
        struct ticket_config *ticket = iter->data;

        if (!fn(ticket, user_data)) {
            return false;
        }
    }
    return true;
}

/*!
 * \internal
 * \brief Call a function for each configured ticket, without modifying it
 *
 * \param[in]     conf       Booth configuration
 * \param[in]     fn         Function to call for each ticket in \p conf
 *                           (returns \c true to continue iterating over the
 *                           rest of the tickets, or \c false to stop)
 * \param[in,out] user_data  User data to pass to \p fn
 *
 * \return \c false if any \p fn call returned \c false, or \c true otherwise
 */
bool
booth__foreach_const_ticket(const struct booth_config *conf,
                            bool (*fn)(const struct ticket_config *, void *),
                            void *user_data)
{
    for (const GSList *iter = conf->tickets; iter != NULL; iter = iter->next) {
        const struct ticket_config *ticket = iter->data;

        if (!fn(ticket, user_data)) {
            return false;
        }
    }
    return true;
}

/* Untrusted input, must fit (incl. \0) in a boothc_ticket. */
bool
valid_ticket_name(const char *s)
{
	for (int i = 0; i < sizeof(boothc_ticket); i++) {
		if (s[i] == 0) {
			return true;
		}
	}

	return false;
}

struct check_ticket_name_data {
    const char *name;
    const struct ticket_config *found;
};

static bool
check_ticket_name(const struct ticket_config *ticket, void *user_data)
{
    struct check_ticket_name_data *data = user_data;

    if (strcmp(ticket->name, data->name) != 0) {
        // No match, so keep iterating
        return true;
    }

    // Match found, so stop iterating
    data->found = ticket;
    return false;
}

bool
find_ticket_by_name(const struct booth_config *conf, const char *name,
                    struct ticket_config **found)
{
    struct check_ticket_name_data data = {
        .name = name,
        .found = NULL,
    };

    booth__foreach_const_ticket(conf, check_ticket_name, &data);

    if (found != NULL) {
        // Cast away const
        *found = (struct ticket_config *) data.found;
    }
    return (data.found != NULL);
}

bool
check_ticket(const struct booth_config *conf, const char *name,
             struct ticket_config **found)
{
	if (found) {
		*found = NULL;
	}

	if (conf == NULL) {
		return false;
	}

	if (!valid_ticket_name(name)) {
		return false;
	}

	return find_ticket_by_name(conf, name, found);
}

/* is it safe to commit the grant?
 * if we didn't hear from all sites on the initial grant, we may
 * need to delay the commit
 *
 * TODO: investigate possibility to devise from history whether a
 * missing site could be holding a ticket or not
 */
static int
ticket_dangerous(const struct booth_config *conf, struct ticket_config *tk)
{
	int tdiff;
	/* we may be invoked often, don't spam the log unnecessarily
	 */
	static int no_log_delay_msg;

	if (!is_time_set(&tk->delay_commit)) {
		return 0;
	}

	if (is_past(&tk->delay_commit) || all_sites_replied(conf, tk)) {
		if (tk->leader == local) {
			const char *str = "all sites replied";

			if (is_past(&tk->delay_commit)) {
				str = "ticket_delay_expired";
			}
			booth__ticket_info(tk, "%s, committing to CIB", str);
		}

		time_reset(&tk->delay_commit);
		no_log_delay_msg = 0;
		return 0;
	}

	tdiff = time_left(&tk->delay_commit);
	booth__ticket_debug(tk,
			    "delay ticket commit for another " intfmt(tdiff));

	if (!no_log_delay_msg) {
		booth__ticket_info(tk,
				   "delaying ticket commit to CIB for "
				   intfmt(tdiff));
		booth__ticket_info(tk, "(or all sites are reached)");
		no_log_delay_msg = 1;
	}

	return 1;
}

int
ticket_write(const struct booth_config *conf, struct ticket_config *tk)
{
	if (local->type != SITE) {
		return -EINVAL;
	}

	if (ticket_dangerous(conf, tk)) {
		return 1;
	}

	if (tk->leader == local) {
		if (tk->state != ST_LEADER) {
			booth__ticket_info(tk,
					   "ticket state not yet consistent, "
					   "delaying ticket grant to CIB");
			return 1;
		}
		pcmk_handler.grant_ticket(conf, tk);
	} else {
		pcmk_handler.revoke_ticket(conf, tk);
	}

	tk->update_cib = false;
	return 0;
}

void
save_committed_tkt(struct ticket_config *tk)
{
	if (!tk->last_valid_tk) {
		tk->last_valid_tk = malloc(sizeof(struct ticket_config));

		if (!tk->last_valid_tk) {
			log_error("out of memory");
			return;
		}
	}

	memcpy(tk->last_valid_tk, tk, sizeof(struct ticket_config));
}

static void
ext_prog_failed(struct booth_config *conf, struct ticket_config *tk,
                int start_election)
{
	if (!is_manual(tk)) {
		/* Give it to somebody else.
	 	 * Just send a VOTE_FOR message, so the
		 * others can start elections. */
		if (!leader_and_valid(tk)) {
			return;
		}

		save_committed_tkt(tk);
		reset_ticket(tk);
		ticket_write(conf, tk);

		if (start_election) {
			ticket_broadcast(conf, tk, OP_VOTE_FOR, OP_REQ_VOTE,
					 RLT_SUCCESS, OR_LOCAL_FAIL);
		}
	} else {
		/* There is not much we can do now because
		 * the manual ticket cannot be relocated.
		 * Just warn the user. */
		if (tk->leader != local) {
			return;
		}

		save_committed_tkt(tk);
		reset_ticket(tk);
		ticket_write(conf, tk);
		log_error("external test failed on the specified machine, cannot acquire a manual ticket");
	}
}

#define attr_found(geo_ap, ap) \
	((geo_ap) && !strcmp((geo_ap)->val, (ap)->attr_val))

int
check_attr_prereq(struct ticket_config *tk, grant_type_e grant_type)
{
	GList *el;
	struct attr_prereq *ap;
	struct geo_attr *geo_ap;

	for (el = g_list_first(tk->attr_prereqs); el; el = g_list_next(el))
	{
		ap = (struct attr_prereq *) el->data;
		if (ap->grant_type != grant_type) {
			continue;
		}

		geo_ap = (struct geo_attr *) g_hash_table_lookup(tk->attr, ap->attr_name);

		switch(ap->op) {
		case ATTR_OP_EQ:
			if (!attr_found(geo_ap, ap)) {
				goto fail;
			}
			break;

		case ATTR_OP_NE:
			if (attr_found(geo_ap, ap)) {
				goto fail;
			}
			break;

		default:
			break;
		}
	}

	return 0;

fail:
	booth__ticket_warn(tk, "'%s' attr-prereq failed", ap->attr_name);
	return 1;
}

/* do we need to run the external program?
 * or we already done that and waiting for the outcome
 * or program exited and we can collect the status
 * return codes
 * 0: no program defined
 * RUNCMD_MORE: program forked, results later
 * != 0: executing program failed (or some other failure)
 */

static int
do_ext_prog(struct booth_config *conf, struct ticket_config *tk,
            int start_election)
{
	int rv = 0;

	if (!tk->clu_test.path) {
		return 0;
	}

	switch(tk->clu_test.progstate) {
	case EXTPROG_IDLE:
		rv = run_handler(conf, tk);
		if (rv == RUNCMD_ERR) {
			booth__ticket_warn(tk,
					   "couldn't run external test, not "
					   "allowed to acquire ticket");
			ext_prog_failed(conf, tk, start_election);
		}
		break;

	case EXTPROG_RUNNING:
		/* should never get here, but just in case */
		rv = RUNCMD_MORE;
		break;

	case EXTPROG_EXITED:
		rv = tk_test_exit_status(tk);
		if (rv) {
			ext_prog_failed(conf, tk, start_election);
		}
		break;

	case EXTPROG_IGNORE:
		/* nothing to do here */
		break;
	}

	return rv;
}

/* Try to acquire a ticket
 * Could be manual grant or after start (if the ticket is granted
 * and still valid in the CIB)
 * If the external program needs to run, this is run twice, once
 * to start the program, and then to get the result and start
 * elections.
 */
static int
acquire_ticket(struct booth_config *conf, struct ticket_config *tk,
               cmd_reason_t reason)
{
	int rv;

	if (reason == OR_ADMIN && check_attr_prereq(tk, GRANT_MANUAL)) {
		return RLT_ATTR_PREREQ;
	}

	switch(do_ext_prog(conf, tk, 0)) {
	case 0:
		/* everything fine */
		break;

	case RUNCMD_MORE:
		/* need to wait for the outcome before starting elections */
		return 0;

	default:
		return RLT_EXT_FAILED;
	}

	if (is_manual(tk)) {
		rv = manual_selection(conf, tk, local, 1, reason);
	} else {
		rv = new_election(conf, tk, local, 1, reason);
	}

	return rv ? RLT_SYNC_FAIL : 0;
}

/** Try to get the ticket for the local site.
 * */
static int
do_grant_ticket(struct booth_config *conf, struct ticket_config *tk,
                int options)
{
	int rv;

	booth__ticket_info(tk, "granting ticket");

	if (tk->leader == local) {
		return RLT_SUCCESS;
	}

	if (is_owned(tk)) {
		if (is_manual(tk) && (options & OPT_IMMEDIATE)) {
			/* -F flag has been used while granting a manual ticket.
			 * The ticket will be granted and may end up being granted
			 * on multiple sites */
			booth__ticket_warn(tk,
					   "manual ticket forced to be "
					   "granted! be aware that you may end "
					   "up having two sites holding the "
					   "same manual ticket! revoke the "
					   "ticket from the unnecessary site!");
		} else {
			return RLT_OVERGRANT;
		}
	}

	set_future_time(&tk->delay_commit, tk->term_duration + tk->acquire_after);

	if (options & OPT_IMMEDIATE) {
		booth__ticket_warn(tk,
				   "granting ticket immediately! If there are "
				   "unreachable sites, _hope_ you are sure "
				   "that they don't have the ticket!");
		time_reset(&tk->delay_commit);
	}

	rv = acquire_ticket(conf, tk, OR_ADMIN);

	if (rv) {
		time_reset(&tk->delay_commit);
		return rv;
	} else {
		return RLT_MORE;
	}
}

static void
start_revoke_ticket(struct booth_config *conf, struct ticket_config *tk)
{
	booth__ticket_info(tk, "revoking ticket");

	save_committed_tkt(tk);
	reset_ticket_and_set_no_leader(tk);
	ticket_write(conf, tk);
	ticket_broadcast(conf, tk, OP_REVOKE, OP_ACK, RLT_SUCCESS, OR_ADMIN);
}

/** Ticket revoke.
 * Only to be started from the leader. */
static int
do_revoke_ticket(struct booth_config *conf, struct ticket_config *tk)
{
	if (tk->acks_expected) {
		booth__ticket_info(tk,
				   "delay ticket revoke until the current "
				   "operation finishes");
		set_next_state(tk, ST_INIT);
		return RLT_MORE;
	} else {
		start_revoke_ticket(conf, tk);
		return RLT_SUCCESS;
	}
}

struct num_sites_granted_data {
    const struct ticket_config *ticket;
    int count;
};

static bool
count_site_if_granted(const struct booth_site *site, void *user_data)
{
    struct num_sites_granted_data *data = user_data;

    if (data->ticket->sites_where_granted[site->index]) {
        data->count++;
    }
    return true;
}

static int
num_sites_granted(const struct booth_config *conf,
                  const struct ticket_config *ticket)
{
    struct num_sites_granted_data data = {
        .ticket = ticket,
        .count = 0,
    };

    booth__foreach_const_site(conf, count_site_if_granted, &data);
    return data.count;
}

static bool
list_ticket(struct ticket_config *ticket, void *user_data)
{
    GString *buf = user_data;

    g_string_append_printf(buf, "ticket: %s, leader: %s", ticket->name,
                           ticket_leader_string(ticket));

    if (is_owned(ticket)) {
        g_string_append(buf, ", expires: ");

        if (!is_manual(ticket) && is_time_set(&ticket->term_expires)) {
            // Manual tickets don't have term_expires defined
            char timeout_str[64] = { '\0', };
            time_t ts = wall_ts(&ticket->term_expires);

            strftime(timeout_str, sizeof(timeout_str), "%F %T", localtime(&ts));
            g_string_append(buf, timeout_str);

        } else {
            g_string_append(buf, "INF");
        }

        if ((ticket->leader == local)
            && is_time_set(&ticket->delay_commit)
            && !is_past(&ticket->delay_commit)) {

            char until_str[64] = { '\0', };
            time_t ts = wall_ts(&ticket->delay_commit);

            strftime(until_str, sizeof(until_str), "%F %T", localtime(&ts));
            g_string_append_printf(buf, " (commit pending until %s)",
                                   until_str);
        }
    }

    if (is_manual(ticket)) {
        g_string_append(buf, " [manual mode]");
    }

    g_string_append_c(buf, '\n');
    return true;
}

struct warn_for_site_if_granted_data {
    const struct ticket_config *ticket;
    GString *buf;
    bool first;
};

static bool
warn_for_site_if_granted(const struct booth_site *site, void *user_data)
{
    struct warn_for_site_if_granted_data *data = user_data;

    if (!data->ticket->sites_where_granted[site->index]) {
        // Ticket is not granted to this site
        return true;
    }

    // Append site name to the (string) list of nodes where ticket is granted
    if (!data->first) {
        g_string_append(data->buf, ", ");
        data->first = true;
    }
    g_string_append(data->buf, site_string(site));
    return true;
}

struct warn_if_multiple_grants_data {
    const struct booth_config *conf;
    GString *buf;
};

static bool
warn_if_multiple_grants(const struct ticket_config *ticket, void *user_data)
{
    struct warn_if_multiple_grants_data *data = user_data;
    struct warn_for_site_if_granted_data site_data = {
        .ticket = ticket,
        .buf = data->buf,
        .first = true,
    };

    if (num_sites_granted(data->conf, ticket) <= 1) {
        // Nothing to warn about; continue checking the rest of the tickets
        return true;
    }

    g_string_append_printf(data->buf,
                           "\nWARNING: The ticket %s is granted to multiple "
                           "sites: ",
                           ticket->name);

    booth__foreach_const_site(data->conf, warn_for_site_if_granted, &site_data);

    g_string_append(data->buf, ". Revoke the ticket from the faulty sites.\n");
    return true;
}

static GString *
list_tickets(struct booth_config *conf)
{
    GString *buf = g_string_sized_new(BUFSIZ);
    struct warn_if_multiple_grants_data data = {
        .conf = conf,
        .buf = buf,
    };

    booth__foreach_ticket(conf, list_ticket, buf);
    booth__foreach_const_ticket(conf, warn_if_multiple_grants, &data);

    return buf;
}

void
disown_ticket(struct ticket_config *tk)
{
	set_leader(tk, NULL);
	tk->is_granted = false;
	get_time(&tk->term_expires);
}

void
reset_ticket(struct ticket_config *tk)
{
	ignore_ext_test(tk);
	disown_ticket(tk);
	no_resends(tk);
	set_state(tk, ST_INIT);
	set_next_state(tk, 0);
	tk->voted_for = NULL;
}

void
reset_ticket_and_set_no_leader(struct ticket_config *tk)
{
	mark_ticket_as_revoked_from_leader(tk);
	reset_ticket(tk);

	tk->leader = no_leader;
	booth__ticket_debug(tk, "ticket leader set to no_leader");
}

static void
log_reacquire_reason(struct ticket_config *tk)
{
	int valid;
	const char *where_granted = NULL;
	char buff[75];

	valid = is_time_set(&tk->term_expires) && !is_past(&tk->term_expires);

	if (tk->leader == local) {
		where_granted = "granted here";
	} else {
		snprintf(buff, sizeof(buff), "granted to %s",
			 site_string(tk->leader));
		where_granted = buff;
	}

	if (!valid) {
		booth__ticket_warn(tk,
				   "%s, but not valid anymore (will try to "
				   "reacquire)", where_granted);
	}

	if (tk->is_granted && tk->leader != local) {
		if (tk->leader && tk->leader != no_leader) {
			booth__ticket_err(tk,
					  "granted here, but also %s, that's "
					  "really too bad (will try to "
					  "reacquire)",
					  where_granted);
		} else {
			booth__ticket_warn(tk,
					   "granted here, but we're not "
					   "recorded as the grantee (will try "
					   "to reacquire)");
		}
	}
}

void
update_ticket_state(const struct booth_config *conf, struct ticket_config *tk,
                    struct booth_site *sender)
{
	if (tk->state == ST_CANDIDATE) {
		booth__ticket_info(tk,
				   "learned from %s about newer ticket, "
				   "stopping elections",
				   site_string(sender));
		/* there could be rejects coming from others; don't log
		 * warnings unnecessarily */
		tk->expect_more_rejects = true;
	}

	if (tk->leader == local || tk->is_granted) {
		/* message from a live leader with valid ticket? */
		if (sender == tk->leader && term_time_left(tk)) {
			if (tk->is_granted) {
				booth__ticket_warn(tk,
						   "ticket was granted here, "
						   "but it's live at %s "
						   "(revoking here)",
						   site_string(sender));
			} else {
				booth__ticket_info(tk, "ticket live at %s",
						   site_string(sender));
			}

			disown_ticket(tk);
			ticket_write(conf, tk);
			set_state(tk, ST_FOLLOWER);
			set_next_state(tk, ST_FOLLOWER);
		} else {
			if (tk->state == ST_CANDIDATE) {
				set_state(tk, ST_FOLLOWER);
			}

			set_next_state(tk, ST_LEADER);
		}
	} else {
		if (!tk->leader || tk->leader == no_leader) {
			if (sender) {
				booth__ticket_info(tk, "ticket is not granted");
			} else {
				booth__ticket_info(tk,
						   "ticket is not granted "
						   "(from CIB)");
			}

			set_state(tk, ST_INIT);
		} else {
			if (sender) {
				const char *sender_s = site_string(sender);

				if (sender == tk->leader) {
					sender_s = "they";
				}
				booth__ticket_info(tk,
						   "ticket granted to %s "
						   "(says %s)",
						   site_string(tk->leader),
						   sender_s);

			} else {
				booth__ticket_info(tk,
						   "ticket granted to %s (from "
						   "CIB)",
						   site_string(tk->leader));
			}

			set_state(tk, ST_FOLLOWER);
			/* just make sure that we check the ticket soon */
			set_next_state(tk, ST_FOLLOWER);
		}
	}
}

bool
booth__setup_ticket(struct ticket_config *ticket, void *user_data)
{
    struct booth_config *conf = user_data;

    reset_ticket(ticket);

    if (local->type == SITE) {
        if (!pcmk_handler.load_ticket(conf, ticket)) {
            update_ticket_state(conf, ticket, NULL);
        }

        ticket->update_cib = true;
    }

    // Wait until all send their status (or until the first timeout)
    ticket->start_postpone = true;

    booth__ticket_info(ticket, "broadcasting state query");
    ticket_broadcast(conf, ticket, OP_STATUS, OP_MY_INDEX, RLT_SUCCESS, 0);
    return true;
}

int
ticket_answer_list(struct booth_config *conf, int fd)
{
    struct boothc_hdr_msg hdr = { 0, };
    int rv = 0;
    GString *data = list_tickets(conf);

    init_header(conf, &hdr.header, CL_LIST, 0, 0, RLT_SUCCESS, 0,
                sizeof(hdr) + data->len);
    rv = send_header_plus(conf, fd, &hdr, data->str, data->len);

    g_string_free(data, TRUE);
    return rv;
}

int
process_client_request(struct booth_config *conf, struct client *req_client,
                       void *buf)
{
	int rv, rc = 1;
	struct ticket_config *tk;
	int cmd;
	struct boothc_ticket_msg omsg;
	struct boothc_ticket_msg *msg;

	msg = (struct boothc_ticket_msg *)buf;
	cmd = ntohl(msg->header.cmd);
	if (!check_ticket(conf, msg->ticket.id, &tk)) {
		log_warn("client referenced unknown ticket %s", msg->ticket.id);
		rv = RLT_INVALID_ARG;
		goto reply_now;
	}

	/* Perform the initial check before granting
	 * an already granted non-manual ticket */
	if (!is_manual(tk) && cmd == CMD_GRANT && is_owned(tk)) {
		log_warn("client wants to grant an (already granted!) ticket %s",
			 msg->ticket.id);

		rv = RLT_OVERGRANT;
		goto reply_now;
	}

	if (cmd == CMD_REVOKE && !is_owned(tk)) {
		log_info("client wants to revoke a free ticket %s", msg->ticket.id);
		rv = RLT_TICKET_IDLE;
		goto reply_now;
	}

	if (cmd == CMD_REVOKE && tk->leader != local) {
		booth__ticket_info(tk, "not granted here, redirect to %s",
				   ticket_leader_string(tk));
		rv = RLT_REDIRECT;
		goto reply_now;
	}

	if (cmd == CMD_REVOKE) {
		rv = do_revoke_ticket(conf, tk);
	} else {
		rv = do_grant_ticket(conf, tk, ntohl(msg->header.options));
	}

	if (rv == RLT_MORE) {
		/* client may receive further notifications, save the
		 * request for further processing */
		add_req(tk, req_client, msg);
		booth__ticket_debug(tk, "queue request %s for client %d",
				    state_to_string(cmd), req_client->fd);
		rc = 0; /* we're not yet done with the message */
	}

reply_now:
	init_ticket_msg(conf, &omsg, CL_RESULT, 0, rv, 0, tk);
	send_client_msg(conf, req_client->fd, &omsg);
	return rc;
}

int
notify_client(struct booth_config *conf, struct ticket_config *tk,
              int client_fd, struct boothc_ticket_msg *msg)
{
	struct boothc_ticket_msg omsg;
	int rv = 0;
	int rc = 0;
	int cmd, options;
	struct client *client = NULL;

	cmd = ntohl(msg->header.cmd);
	options = ntohl(msg->header.options);
	rv = tk->outcome;

	client = booth__find_client(client_fd);
	if (client == NULL) {
		booth__ticket_info(tk,
				   "client %d (request %s) left before being "
				   "notified",
				   client_fd, state_to_string(cmd));
		return 0;
	}

	booth__ticket_debug(tk, "notifying client %d (request %s)", client_fd,
			    state_to_string(cmd));
	init_ticket_msg(conf, &omsg, CL_RESULT, 0, rv, 0, tk);
	rc = send_client_msg(conf, client_fd, &omsg);

	if (rc == 0 && (rv == RLT_MORE ||
			(rv == RLT_CIB_PENDING && (options & OPT_WAIT_COMMIT)))) {
		/* more to do here, keep the request */
		return 1;
	} else {
		/* we sent a definite answer or there was a write error, drop
		 * the client */
		if (rc) {
			booth__ticket_debug(tk,
					    "failed to notify client %d "
					    "(request %s)",
					    client_fd, state_to_string(cmd));
		} else {
			booth__ticket_debug(tk,
					    "client %d (request %s) got final "
					    "notification",
					    client_fd, state_to_string(cmd));
		}

		booth__remove_client(client->index);
		return 0; /* we're done with this request */
	}
}

int
ticket_broadcast(struct booth_config *conf, struct ticket_config *tk,
                 cmd_request_t cmd, cmd_request_t expected_reply,
                 cmd_result_t res, cmd_reason_t reason)
{
	struct boothc_ticket_msg msg;

	init_ticket_msg(conf, &msg, cmd, 0, res, reason, tk);
	booth__ticket_debug(tk, "broadcasting '%s' (term=%d, valid=%d)",
			    state_to_string(cmd), ntohl(msg.ticket.term),
			    msg_term_time(&msg));

	tk->last_request = cmd;

	if (expected_reply) {
		expect_replies(tk, expected_reply);
	}

	ticket_activate_timeout(tk);
	return conf->transport->broadcast_auth(conf, &msg, sendmsglen(&msg));
}

/* update the ticket on the leader, write it to the CIB, and
   send out the update message to others with the new expiry
   time
*/
int
leader_update_ticket(struct booth_config *conf, struct ticket_config *tk)
{
	int rv = 0, rv2;
	timetype now;

	if (tk->ticket_updated >= 2) {
		return 0;
	}

	/* for manual tickets, we don't set time expiration */
	if (!is_manual(tk) && tk->ticket_updated < 1) {
		tk->ticket_updated = 1;
		get_time(&now);
		copy_time(&now, &tk->last_renewal);
		set_future_time(&tk->term_expires, tk->term_duration);
		rv = ticket_broadcast(conf, tk, OP_UPDATE, OP_ACK, RLT_SUCCESS, 0);
	}

	if (tk->ticket_updated < 2) {
		rv2 = ticket_write(conf, tk);
		switch(rv2) {
		case 0:
			tk->ticket_updated = 2;
			tk->outcome = RLT_SUCCESS;
			foreach_tkt_req(conf, tk, notify_client);
			break;

		case 1:
			if (tk->outcome != RLT_CIB_PENDING) {
				tk->outcome = RLT_CIB_PENDING;
				foreach_tkt_req(conf, tk, notify_client);
			}
			break;

		default:
			break;
		}
	}

	return rv;
}

static bool
log_site_if_lost(const struct booth_site *site, void *user_data)
{
    struct ticket_config *ticket = user_data;

    if ((ticket->acks_received & site->bitmask) != 0) {
        // Site is not lost; continue checking the rest of the sites
        return true;
    }

    booth__ticket_warn(ticket,
                       "%s %s didn't acknowledge our %s, will retry %d times",
                       ((site->type == ARBITRATOR)? "arbitrator" : "site"),
                       site_string(site), state_to_string(ticket->last_request),
                       ticket->retries);
    return true;
}

struct resend_if_needed_data {
    struct booth_config *conf;
    struct ticket_config *ticket;
};

static bool
resend_if_needed(struct booth_site *site, void *user_data)
{
    struct resend_if_needed_data *data = user_data;

    if ((data->ticket->acks_received & site->bitmask) != 0) {
        // Already received, so resend is not necessary
        return true;
    }

    site->resend_cnt++;
    booth__ticket_debug(data->ticket, "resending %s to %s",
                        state_to_string(data->ticket->last_request),
                        site_string(site));
    send_msg(data->conf, data->ticket->last_request, data->ticket, site, NULL);
    return true;
}

static void
resend_msg(struct booth_config *conf, struct ticket_config *tk)
{
    struct resend_if_needed_data data = {
        .conf = conf,
        .ticket = tk,
    };

    if ((tk->acks_received ^ local->bitmask) == 0) {
        ticket_broadcast(conf, tk, tk->last_request, 0, RLT_SUCCESS, 0);
        return;
    }

    booth__foreach_site(conf, resend_if_needed, &data);
    ticket_activate_timeout(tk);
}

static void
handle_resends(struct booth_config *conf, struct ticket_config *tk)
{
	int ack_cnt;

	if (++tk->retry_number > tk->retries) {
		booth__ticket_info(tk, "giving up on sending retries");
		no_resends(tk);
		set_ticket_wakeup(tk);
		return;
	}

	/* try to reach some sites again if we just stepped down */
	if (tk->last_request == OP_VOTE_FOR) {
		booth__ticket_warn(tk,
				   "no answers to our VtFr request to step "
				   "down (try #%d), we are alone",
				   tk->retry_number);
		goto just_resend;
	}

	if (!majority_of_bits(conf, tk, tk->acks_received)) {
		ack_cnt = count_bits(tk->acks_received) - 1;

		if (!ack_cnt) {
			booth__ticket_warn(tk,
					   "no answers to our request "
					   "(try #%d), we are alone",
					   tk->retry_number);
		} else {
			booth__ticket_warn(tk,
					   "not enough answers to our request "
					   "(try #%d): only got %d answers",
					   tk->retry_number, ack_cnt);
		}

	} else if (tk->retry_number == 1) {
		// Log only on the first retry
		booth__foreach_const_site(conf, log_site_if_lost, tk);
	}

just_resend:
	resend_msg(conf, tk);
}

static int
postpone_ticket_processing(struct ticket_config *tk)
{
	extern timetype start_time;

	return tk->start_postpone && (-time_left(&start_time) < tk->timeout);
}

#define has_extprog_exited(tk) ((tk)->clu_test.progstate == EXTPROG_EXITED)

static void
process_next_state(struct booth_config *conf, struct ticket_config *tk)
{
	int rv;

	switch(tk->next_state) {
	case ST_LEADER:
		if (has_extprog_exited(tk)) {
			if (tk->state == ST_LEADER) {
				break;
			}

			rv = acquire_ticket(conf, tk, OR_ADMIN);
			if (rv != 0) { /* external program failed */
				tk->outcome = rv;
				foreach_tkt_req(conf, tk, notify_client);
			}
		} else {
			log_reacquire_reason(tk);
			acquire_ticket(conf, tk, OR_REACQUIRE);
		}
		break;

	case ST_INIT:
		no_resends(tk);
		start_revoke_ticket(conf, tk);
		tk->outcome = RLT_SUCCESS;
		foreach_tkt_req(conf, tk, notify_client);
		break;

	/* wanting to be follower is not much of an ambition; no
	 * processing, just return; don't reset start_postpone until
	 * we got some replies to status */
	case ST_FOLLOWER:
		return;

	default:
		break;
	}

	tk->start_postpone = false;
}

static void
ticket_lost(const struct booth_config *conf, struct ticket_config *tk)
{
	int reason = OR_TKT_LOST;

	if (tk->leader != local) {
		booth__ticket_warn(tk, "lost at %s", site_string(tk->leader));
	} else {
		if (is_ext_prog_running(tk)) {
			ext_prog_timeout(tk);
			reason = OR_LOCAL_FAIL;
		} else {
			booth__ticket_warn(tk,
					   "lost majority (revoking locally)");
			reason = tk->election_reason ? tk->election_reason : OR_REACQUIRE;
		}
	}

	tk->lost_leader = tk->leader;
	save_committed_tkt(tk);
	mark_ticket_as_revoked_from_leader(tk);
	reset_ticket(tk);
	set_state(tk, ST_FOLLOWER);

	if (local->type == SITE) {
		ticket_write(conf, tk);
		schedule_election(tk, reason);
	}
}

static void
next_action(struct booth_config *conf, struct ticket_config *tk)
{
	int rv;

	switch(tk->state) {
	case ST_INIT:
		/* init state, handle resends for ticket revoke */
		/* and rebroadcast if stepping down */
		/* try to acquire ticket on grant */
		if (has_extprog_exited(tk)) {
			rv = acquire_ticket(conf, tk, OR_ADMIN);
			if (rv != 0) { /* external program failed */
				tk->outcome = rv;
				foreach_tkt_req(conf, tk, notify_client);
			}
		} else {
			if (tk->acks_expected) {
				handle_resends(conf, tk);
			}
		}
		break;

	case ST_FOLLOWER:
		if (!is_manual(tk)) {
			/* leader/ticket lost? and we didn't vote yet */
			booth__ticket_debug(tk, "leader: %s, voted_for: %s",
					    site_string(tk->leader),
					    site_string(tk->voted_for));

			if (tk->leader) {
				break;
			}

			if (!tk->voted_for || !tk->in_election) {
				disown_ticket(tk);
				if (!new_election(conf, tk, NULL, 1, OR_AGAIN)) {
					ticket_activate_timeout(tk);
				}
			} else {
				/* we should restart elections in case nothing
				* happens in the meantime */
				tk->in_election = false;
				ticket_activate_timeout(tk);
			}
		} else {
			/* for manual tickets, also try to acquire ticket on grant
			 * in the Follower state (because we may end up having
			 * two Leaders) */
			if (has_extprog_exited(tk)) {
				rv = acquire_ticket(conf, tk, OR_ADMIN);
				if (rv != 0) { /* external program failed */
					tk->outcome = rv;
					foreach_tkt_req(conf, tk, notify_client);
				}
			} else {
				/* Otherwise, just send ACKs if needed */
				if (tk->acks_expected) {
					handle_resends(conf, tk);
				}
			}
		}
		break;

	case ST_CANDIDATE:
		/* elections timed out? */
		elections_end(conf, tk);
		break;

	case ST_LEADER:
		/* timeout or ticket renewal? */
		if (tk->acks_expected) {
			handle_resends(conf, tk);
			if (majority_of_bits(conf, tk, tk->acks_received)) {
				leader_update_ticket(conf, tk);
			}
		} else if (!do_ext_prog(conf, tk, 1)) {
			/* this is ticket renewal, run local test */
			ticket_broadcast(conf, tk, OP_HEARTBEAT, OP_ACK, RLT_SUCCESS, 0);
			tk->ticket_updated = 0;
		}

		break;

	default:
		break;
	}
}

static void
ticket_cron(struct booth_config *conf, struct ticket_config *tk)
{
	/* don't process the tickets too early after start */
	if (postpone_ticket_processing(tk)) {
		booth__ticket_debug(tk,
				    "ticket processing postponed "
				    "(start_postpone=%d)", tk->start_postpone);
		/* but run again soon */
		ticket_activate_timeout(tk);
		return;
	}

	/* no need for status resends, we hope we got at least one
	 * my_index back */
	if (tk->acks_expected == OP_MY_INDEX) {
		no_resends(tk);
	}

	/* after startup, we need to decide what to do based on the
	 * current ticket state; tk->next_state has a hint
	 * also used for revokes which had to be delayed
	 */
	if (tk->next_state) {
		process_next_state(conf, tk);
		goto out;
	}

	/* Has an owner, has an expiry date, and expiry date in the past?
	 * For automatic tickets, losing the ticket must happen
	 * in _every_ state.
	 */
	if (!is_manual(tk) && is_owned(tk) && is_time_set(&tk->term_expires) &&
	    is_past(&tk->term_expires)) {
		ticket_lost(conf, tk);
		goto out;
	}

	next_action(conf, tk);

out:
	tk->next_state = 0;
	if (!tk->in_election && tk->update_cib) {
		ticket_write(conf, tk);
	}
}

bool
booth__process_ticket(struct ticket_config *ticket, void *user_data)
{
    struct booth_config *conf = user_data;
    timetype last_cron = { 0, };

    if (!has_extprog_exited(ticket)
        && is_time_set(&ticket->next_cron) && !is_past(&ticket->next_cron)) {

        return true;
    }

    booth__ticket_debug(ticket, "ticket cron");

    copy_time(&ticket->next_cron, &last_cron);
    ticket_cron(conf, ticket);

    if (time_cmp(&last_cron, &ticket->next_cron, ==)) {
        booth__ticket_debug(ticket, "nobody set ticket wakeup");
        set_ticket_wakeup(ticket);
    }

    return true;
}

bool
booth__log_ticket_info(struct ticket_config *ticket, void *user_data)
{
    time_t ts = wall_ts(&ticket->term_expires);

    booth__ticket_info(ticket, "state '%s' term %d leader %s expires %-24.24s",
                       state_to_string(ticket->state), ticket->current_term,
                       ticket_leader_string(ticket), ctime(&ts));
    return true;
}

static void
update_acks(const struct booth_config *conf, struct ticket_config *tk,
            struct booth_site *sender, struct booth_site *leader,
            struct boothc_ticket_msg *msg)
{
	uint32_t cmd;
	uint32_t req;

	cmd = ntohl(msg->header.cmd);
	req = ntohl(msg->header.request);
	if (req != tk->last_request ||
	    (tk->acks_expected != cmd && tk->acks_expected != OP_REJECTED)) {
		return;
	}

	/* got an ack! */
	tk->acks_received |= sender->bitmask;

	if (all_replied(conf, tk) ||
	    /* we just stepped down, need only one site to start elections */
	    (cmd == OP_REQ_VOTE && tk->last_request == OP_VOTE_FOR)) {
		no_resends(tk);
		tk->start_postpone = false;
		set_ticket_wakeup(tk);
	}
}

/* read ticket message */
int
ticket_recv(struct booth_config *conf, void *buf, struct booth_site *source)
{
	struct boothc_ticket_msg *msg;
	struct ticket_config *tk;
	struct booth_site *leader;
	uint32_t leader_u;

	msg = (struct boothc_ticket_msg *)buf;

	if (!check_ticket(conf, msg->ticket.id, &tk)) {
		log_warn("got invalid ticket name %s from %s",
			 msg->ticket.id, site_string(source));
		source->invalid_cnt++;
		return -EINVAL;
	}


	leader_u = ntohl(msg->ticket.leader);
	if (!find_site_by_id(conf, leader_u, &leader)) {
		booth__ticket_err(tk, "message with unknown leader %u received",
				  leader_u);
		source->invalid_cnt++;
		return -EINVAL;
	}

	update_acks(conf, tk, source, leader, msg);
	return raft_answer(conf, tk, source, leader, msg);
}

static void
log_next_wakeup(struct ticket_config *tk)
{
	int left;

	left = time_left(&tk->next_cron);
	booth__ticket_debug(tk, "set ticket wakeup in " intfmt(left));
}

/* New vote round; §5.2 */
/* delay the next election start for some random time
 * (up to 1 second)
 */
void
add_random_delay(struct ticket_config *tk)
{
	timetype tv;

	interval_add(&tk->next_cron, rand_time(min(1000, tk->timeout)), &tv);
	ticket_next_cron_at(tk, &tv);

	if (ANYDEBUG) {
		log_next_wakeup(tk);
	}
}

void
set_ticket_wakeup(struct ticket_config *tk)
{
	timetype near_future, tv, next_vote;

	set_future_time(&near_future, 10);

	if (!is_manual(tk)) {
		/* At least every hour, perhaps sooner (default) */
		booth__ticket_debug(tk,
				    "ticket will be woken up after up to one "
				    "hour");
		ticket_next_cron_in(tk, 3600*TIME_RES);

		switch (tk->state) {
		case ST_LEADER:
			assert(tk->leader == local);

			get_next_election_time(tk, &next_vote);

			/* If timestamp is in the past, wakeup in
			* near future */
			if (!is_time_set(&next_vote)) {
				booth__ticket_debug(tk,
						    "next ts unset, wakeup "
						    "soon");
				ticket_next_cron_at(tk, &near_future);
			} else if (is_past(&next_vote)) {
				int tdiff = time_left(&next_vote);

				booth__ticket_debug(tk,
						    "next ts in the past "
						    intfmt(tdiff));
				ticket_next_cron_at(tk, &near_future);
			} else {
				ticket_next_cron_at(tk, &next_vote);
			}
			break;

		case ST_CANDIDATE:
			assert(is_time_set(&tk->election_end));
			ticket_next_cron_at(tk, &tk->election_end);
			break;

		case ST_INIT:
		case ST_FOLLOWER:
			/* If there is (or should be) some owner, check on it later on.
			* If no one is interested - don't care. */
			if (is_owned(tk)) {
				interval_add(&tk->term_expires, tk->acquire_after, &tv);
				ticket_next_cron_at(tk, &tv);
			}

			break;

		default:
			booth__ticket_err(tk, "unknown ticket state: %d",
					  tk->state);
		}

		if (tk->next_state) {
			/* we need to do something soon here */
			if (!tk->acks_expected) {
				ticket_next_cron_at(tk, &near_future);
			} else {
				ticket_activate_timeout(tk);
			}
		}
	} else {
		/* At least six minutes, to make sure that multi-leader situations
		 * will be solved promptly.
		 */
		booth__ticket_debug(tk,
				    "manual ticket will be woken up after up "
				    "to six minutes");
		ticket_next_cron_in(tk, 60 * TIME_RES);

		/* For manual tickets, no earlier timeout could be set in a similar
		 * way as it is done in a switch above for automatic tickets.
		 * The reason is that term's timeout is INF and no Raft-based elections
		 * are performed.
		 */
	}

	if (ANYDEBUG) {
		log_next_wakeup(tk);
	}
}

void
schedule_election(struct ticket_config *tk, cmd_reason_t reason)
{
	if (local->type != SITE) {
		return;
	}

	tk->election_reason = reason;
	get_time(&tk->next_cron);
	/* introduce a short delay before starting election */
	add_random_delay(tk);
}

int
is_manual(struct ticket_config *tk)
{
	return (tk->mode == TICKET_MODE_MANUAL) ? 1 : 0;
}

/* Given a state (in host byte order), return a human-readable (char*).
 * An array is used so that multiple states can be printed in a single printf(). */
char *
state_to_string(uint32_t state_ho)
{
	union mu { cmd_request_t s; char c[5]; };
	static union mu cache[6] = { { 0 } }, *cur;
	static int current = 0;

	current ++;
	if (current >= sizeof(cache)/sizeof(cache[0])) {
		current = 0;
	}

	cur = cache + current;

	cur->s = htonl(state_ho);
	/* Shouldn't be necessary, union array is initialized with zeroes, and
	 * these bytes never get written. */
	cur->c[4] = 0;
	return cur->c;
}

int
send_reject(struct booth_config *conf, struct booth_site *dest,
            struct ticket_config *tk, cmd_result_t code,
            struct boothc_ticket_msg *in_msg)
{
	int req = ntohl(in_msg->header.cmd);
	struct boothc_ticket_msg msg;

	booth__ticket_debug(tk, "sending reject to %s", site_string(dest));
	init_ticket_msg(conf, &msg, OP_REJECTED, req, code, 0, tk);
	return conf->transport->send_auth(conf, dest, &msg, sendmsglen(&msg));
}

int
send_msg(struct booth_config *conf, int cmd, struct ticket_config *tk,
         struct booth_site *dest, struct boothc_ticket_msg *in_msg)
{
	int req = 0;
	struct ticket_config *valid_tk = tk;
	struct boothc_ticket_msg msg;

	/* if we want to send the last valid ticket, then if we're in
	 * the ST_CANDIDATE state, the last valid ticket is in
	 * tk->last_valid_tk
	 */
	if (cmd == OP_MY_INDEX) {
		if (tk->state == ST_CANDIDATE && tk->last_valid_tk) {
			valid_tk = tk->last_valid_tk;
		}

		booth__ticket_info(tk, "sending status to %s",
				   site_string(dest));
	}

	if (in_msg) {
		req = ntohl(in_msg->header.cmd);
	}

	init_ticket_msg(conf, &msg, cmd, req, RLT_SUCCESS, 0, valid_tk);
	return conf->transport->send_auth(conf, dest, &msg, sendmsglen(&msg));
}
