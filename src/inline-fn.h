/* 
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

#ifndef _INLINE_FN_H
#define _INLINE_FN_H

#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include "timer.h"
#include "config.h"
#include "transport.h"

static inline bool
is_auth_req(const struct booth_config *conf)
{
    return (conf != NULL) && (conf->authkey[0] != '\0');
}

static inline int
get_local_id(void)
{
	return local ? local->site_id : -1;
}

static inline uint32_t
get_node_id(struct booth_site *node)
{
	return node ? node->site_id : 0;
}

/** Returns number of seconds left, if any. */
static inline int
term_time_left(struct ticket_config *tk)
{
	int left = 0;

	if (is_time_set(&tk->term_expires)) {
		left = time_left(&tk->term_expires);
	}
	return (left < 0) ? 0 : left;
}

static inline int
leader_and_valid(struct ticket_config *tk)
{
	if (tk->leader != local)
		return 0;

	return term_time_left(tk);
}

/** Is this some leader? */
static inline int
is_owned(const struct ticket_config *tk)
{
	return (tk->leader && tk->leader != no_leader);
}

/* get the _real_ message length out of the header
 */
#define sendmsglen(msg) ntohl((msg)->header.length)

static inline void
init_header(const struct booth_config *conf, struct boothc_header *header,
            int cmd, int request, int options, int result, int reason,
            int data_len)
{
    assert((conf != NULL) && (header != NULL) && (local != NULL)
           && (local->site_id != 0));

    header->magic = htonl(BOOTHC_MAGIC);
    header->version = htonl(BOOTHC_VERSION);
    header->from = htonl(local->site_id);
    header->opts = htonl(0);

    if (is_auth_req(conf)) {
        timetype now = { 0, };

        get_time(&now);
        header->secs = htonl(secs_since_epoch(&now));
        header->usecs = htonl(get_usecs(&now));
        header->length = htonl(data_len);

    } else {
        header->secs = htonl(0);
        header->usecs = htonl(0);
        header->length = htonl(data_len - sizeof(struct hmac));
    }

    header->cmd = htonl(cmd);
    header->request = htonl(request);
    header->options = htonl(options);
    header->result = htonl(result);
    header->reason = htonl(reason);
}

#define my_last_term(tk) \
	(((tk)->state == ST_CANDIDATE && (tk)->last_valid_tk) ? \
	(tk)->last_valid_tk->current_term : (tk)->current_term)

extern int TIME_MULT;

#define msg_term_time(msg) \
    (ntohl((msg)->ticket.term_valid_for) * BOOTH__TIME_RES / TIME_MULT)

#define set_msg_term_time(msg, tk) do {                                 \
        (msg)->ticket.term_valid_for =                                  \
            htonl(term_time_left(tk) * TIME_MULT / BOOTH__TIME_RES);    \
    } while (0)

static inline void
init_ticket_msg(const struct booth_config *conf, struct boothc_ticket_msg *msg,
                int cmd, int request, int rv, int reason,
                struct ticket_config *tk)
{
	assert(sizeof(msg->ticket.id) == sizeof(tk->name));

	init_header(conf, &msg->header, cmd, request, 0, rv, reason, sizeof(*msg));

	if (!tk) {
		memset(&msg->ticket, 0, sizeof(msg->ticket));
	} else {
		memcpy(msg->ticket.id, tk->name, sizeof(msg->ticket.id));

		msg->ticket.leader         = htonl(get_node_id(
			(tk->leader && tk->leader != no_leader) ? tk->leader :
				(tk->voted_for ? tk->voted_for : no_leader)));
		msg->ticket.term           = htonl(tk->current_term);
		set_msg_term_time(msg, tk);
	}
}

static inline const char *
site_string(const struct booth_site *site)
{
	return site ? site->addr_string : "NONE";
}

static inline uint16_t
site_port(const struct booth_site *site)
{
	assert(site != NULL);

	if (site->family == AF_INET) {
		return ntohs(site->sa4.sin_port);
	} else if (site->family == AF_INET6) {
		return ntohs(site->sa6.sin6_port);
	} else {
		return 0;
	}
}

static inline const char *
ticket_leader_string(const struct ticket_config *tk)
{
	return site_string(tk->leader);
}

/* only invoked when ticket leader */
static inline void
get_next_election_time(struct ticket_config *tk, timetype *next)
{
	assert(tk->leader == local);

	/* if last_renewal is not set, which is unusual, it may mean
	 * that the ticket never got updated, i.e. nobody acked
	 * ticket updates (say, due to a temporary connection
	 * problem)
	 * we may try a bit later again */
	if (!is_time_set(&tk->last_renewal)) {
		time_reset(next);
	} else {
		interval_add(&tk->last_renewal, tk->renewal_freq, next);
	}

	/* if delay_commit is earlier than next, then set next to
	 * delay_commit */
	if (is_time_set(&tk->delay_commit) &&
			time_cmp(next, &tk->delay_commit, >)) {
		copy_time(&tk->delay_commit, next);
	}
}

static inline void
expect_replies(struct ticket_config *tk, int reply_type)
{
	tk->retry_number = 0;
	tk->acks_expected = reply_type;
	tk->acks_received = local->bitmask;
}

static inline void
no_resends(struct ticket_config *tk)
{
	tk->retry_number = 0;
	tk->acks_expected = 0;
}

static inline int
count_bits(uint64_t val)
{
	return __builtin_popcount(val);
}

static inline int
majority_of_bits(const struct booth_config *conf, struct ticket_config *tk,
                 uint64_t val)
{
	/* Use ">" to get majority decision, even for an even number
	 * of participants. */
	return (count_bits(val) * 2) > conf->site_count;
}

static inline int
all_replied(const struct booth_config *conf, struct ticket_config *tk)
{
	return (tk->acks_received ^ conf->all_bits) == 0;
}

static inline int
all_sites_replied(const struct booth_config *conf, struct ticket_config *tk)
{
	return ((tk->acks_received & conf->sites_bits) ^ conf->sites_bits) == 0;
}

#endif  // _INLINE_FN_H
