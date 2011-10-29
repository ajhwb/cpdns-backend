/*
 * Cool PowerDNS Backend
 *
 * Copyright (C) 2011 - Ardhan Madras <ajhwb@knac.com>
 *
 * This software is free software; you can redistribute it and/or modify it under 
 * the terms of the GNU General Public License as published by the Free Software 
 * Foundation; version 2 of the License.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with 
 * This software; if not, write to the Free Software Foundation, Inc., 51 Franklin 
 * St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include <sqlite3.h>
#include <glib.h>
#include <hiredis/hiredis.h>
#include <ldns/ldns.h>
#include <queue.h>

#define MYSQLS		0x00000001
#define PGSQLS		0x00000002
#define DB_BACKEND	PGSQLS

#if DB_BACKEND == MYSQLS
# include <mysql/mysql.h>
#elif DB_BACKEND == PGSQLS
# include <libpq-fe.h>
#endif

#define CONFIG_FILE	"/etc/pdns/backend.conf"
/* Unique prefix string for each key, example cpdns:x.com ... */
#define KEY_PREFIX	"cpdns"
#define LOG_DIR		"/var/log/pdns"

enum type_id {
	TYPE_ID_Q = 0,
	TYPE_ID_AXFR
};

enum qclass_id {
	QCLASS_ID_IN = 0
};

/* The RR type that supported by this backend */
enum rr_type {
	RR_TYPE_ANY	= LDNS_RR_TYPE_ANY,
	RR_TYPE_A	= LDNS_RR_TYPE_A,
	RR_TYPE_AAAA	= LDNS_RR_TYPE_AAAA,
	RR_TYPE_SOA	= LDNS_RR_TYPE_SOA,
	RR_TYPE_NS	= LDNS_RR_TYPE_NS,
	RR_TYPE_MX	= LDNS_RR_TYPE_MX,
	RR_TYPE_TXT	= LDNS_RR_TYPE_TXT,
	RR_TYPE_CNAME	= LDNS_RR_TYPE_CNAME,
	/* Mark a type that is not handled */
	RR_TYPE_UNDEFINED = LDNS_RR_TYPE_NULL
};

struct query {
	enum type_id type_id;
	enum qclass_id qclass_id;
	enum rr_type qtype_id;
	char type[10];
	char qname[256];
	char qclass[3];
	char qtype[8];
	int id;
	char remote_ip[16];
};

struct answer {
	int qtype;
	int mx_code;
	unsigned int ttl;
	char qname[256];
	char data[256];
};

struct cache_data {
	queue_t *data;
	char *qname;
};

struct config {
	char *host;
	char *username;
	char *password;
	char *database;
	char *cache_host;
	char *log_database;
	char *landing_page;
	unsigned short port;
	unsigned short cache_port;
	int filter;
	int log;
	int debug;
};

struct log {
	long reqtime;     /* Time of query */
	int qtime;        /* Query time in miliseconds */
	int ftime;	  /* Filter query time in miliseconds */
	int blacklist;    /* Blacklist status */
	int exist;        /* Name exist status */
	int status;       /* Query status */
	int qtype;        /* Record type of query */
	char qname[256];  /* Name to query */
	char remote[16];  /* Remote client IP */
};

struct filter_info
{
	int status;        /* Filter status */
	unsigned long id;  /* Client ID */
};

#define NSEC_PER_SEC	1000000000
#define USEC_PER_SEC	1000000

static redisContext *cachedb_ctx;
static ldns_resolver *resolver;
sqlite3 *cachedb;
static struct config config;
static int backend_id;

#if DB_BACKEND == MYSQLS
static MYSQL *my_conn;
#elif DB_BACKEND == PGSQLS
static PGconn *pg_conn;
#endif


int lookup_cachedb(const struct query*, queue_t**);
static void print_answer(const struct answer*, FILE*, int);
static void clear_cachedb(const struct query*);
void free_cachedb_data(queue_t*);
static int search_blacklist(const struct query*, queue_t**, 
				struct filter_info*, struct timespec*);
static int insert_blacklist_data(const struct answer*);
static int insert_log(const struct log*);
static int write_log(const struct log*);
static int init_resolver(void);
static void insert_cachedb(const struct query*, queue_t*, struct timespec);
static void close_database(void);
static void insert_filter_cache(const struct query*, const struct filter_info*);
static int lookup_filter_cache(const struct query*, struct filter_info*);


#define exec_cachedb(cmd) \
do { \
	int ret = sqlite3_exec(cachedb, cmd, 0, 0, 0); \
	if (ret != SQLITE_OK) { \
		fprintf(stderr, "<< %s: %i: %s >>\n", __func__, \
			sqlite3_errcode(cachedb), sqlite3_errmsg(cachedb)); \
		if (sqlite3_errcode(cachedb) != 1) { \
			fprintf(stderr, "<< aborting >>\n"); \
			exit(EXIT_FAILURE); \
		} \
	} \
} while (0);

#define cachedb_error() \
do { \
	fprintf(stderr, "<< %s: %s >>\n", __func__, \
		cachedb_ctx->errstr); \
	exit(EXIT_FAILURE); \
} while (0);


#define cachedb_cmd(cmd, use_reply) \
({ \
	redisReply *reply = redisCommand(cachedb_ctx, cmd); \
	if (!reply) { \
		fprintf(stderr, "<< %s: %s >>\n", __func__, \
			cachedb_ctx->errstr); \
		exit(EXIT_FAILURE); \
	} \
	if ((use_reply) == 0) \
		freeReplyObject(reply); \
	reply; \
})

#define xmalloc(n) \
({ \
	void *ptr = malloc(n); \
	if (ptr == NULL) { \
		fprintf(stderr, "<< malloc fail >>\n"); \
		exit(EXIT_FAILURE); \
	} \
	ptr; \
})

char *xstrndup(const char *src, int len)
{
	int l = len == -1 ? (int) strlen(src) : len;
	char *dst = malloc(l + 1);

	if (dst != NULL) {
		memcpy(dst, src, len);
		*(dst + l) = 0;
	}
	return dst;
}

static const char *rr2str(enum rr_type type)
{
	if (type == RR_TYPE_ANY)
		return "ANY";
	else if (type == RR_TYPE_A)
		return "A";
	else if (type == RR_TYPE_AAAA)
		return "AAAA";
	else if (type == RR_TYPE_SOA)
		return "SOA";
	else if (type == RR_TYPE_MX)
		return "MX";
	else if (type == RR_TYPE_NS)
		return "NS";
	else if (type == RR_TYPE_CNAME)
		return "CNAME";
	else if (type == RR_TYPE_TXT)
		return "TXT";
	else
		return "NULL";
}

struct answer *answer_new(int qtype, unsigned int ttl, const char *qname, const char *data)
{
	struct answer *ans = malloc(sizeof(struct answer));
	if (ans != NULL) {
		ans->qtype = qtype;
		ans->ttl = ttl;
		sprintf(ans->qname, "%s", qname);
		sprintf(ans->data, "%s", data);
	}
	return ans;
}

void answer_free(struct answer *ans)
{
	free(ans);
}

static int init_resolver(void)
{
	ldns_status status;
	const struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };

	resolver = NULL;

	status = ldns_resolver_new_frm_file(&resolver, NULL);

	if (status != LDNS_STATUS_OK)
		return 0;
	/*
	 * Don't know yet how ldns calculate timeout time, time(1) show me
	 * that 1 second tv_sec equals to 3 seconds :|
	 */
	ldns_resolver_set_timeout(resolver, tv);

	return 1;
}

static void destroy_resolver(void)
{
	ldns_resolver_deep_free(resolver);
}

static void set_backend_id(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	srand(ts.tv_nsec);
	backend_id = rand() % 10000;
}

struct timespec ts_diff(const struct timespec *start, const struct timespec *end)
{
	struct timespec ts = { .tv_sec = 0L, .tv_nsec = 0L };
	unsigned long long d1, d2, delta;

	d1 = (unsigned long long) start->tv_sec * NSEC_PER_SEC + start->tv_nsec;
	d2 = (unsigned long long) end->tv_sec * NSEC_PER_SEC + end->tv_nsec;
	delta = d2 - d1;

	while (delta >= NSEC_PER_SEC) {
		++ts.tv_sec;
		delta -= NSEC_PER_SEC;
	}
	ts.tv_nsec = delta;
	return ts;
}

static inline long ts2ms(const struct timespec *ts)
{
	long retval = ts->tv_nsec / USEC_PER_SEC;
	retval += (ts->tv_sec * 1000);

	return retval;
}

const char *type_str(enum rr_type type)
{
	if (type == RR_TYPE_A)
		return "A";
	else if (type == RR_TYPE_AAAA)
		return "AAAA";
	else if (type == RR_TYPE_SOA)
		return "SOA";
	else if (type == RR_TYPE_NS)
		return "NS";
	else if (type == RR_TYPE_MX)
		return "MX";
	else if (type == RR_TYPE_CNAME)
		return "CNAME";
	else if (type == RR_TYPE_TXT)
		return "TXT";
	else
		return "NULL";
}

static void print_answer(const struct answer *ans, FILE *fp, int cached)
{
	static char buffer[BUFSIZ];

	if (ans->qtype == RR_TYPE_MX)
		sprintf(buffer, "DATA\t%s\tIN\t%s\t%u\t1\t%i\t%s",
			ans->qname, type_str(ans->qtype),
			ans->ttl, ans->mx_code, ans->data);
	else
		sprintf(buffer, "DATA\t%s\tIN\t%s\t%u\t1\t%s",
			ans->qname, type_str(ans->qtype),
			ans->ttl, ans->data);

	if (fp == stderr) {
		if (cached)
			fprintf(fp, "%s [c] [ID:%i]\n", buffer, backend_id);
		else
			fprintf(fp, "%s [ID:%i]\n", buffer, backend_id);
	} else {
		fprintf(stdout, "%s\n", buffer);
	}
}

void process_blacklist(const struct query *q, const struct answer *blacklist_ans)
{
	queue_t *cache_data = NULL, *ptr;
	struct answer *ans;

	insert_blacklist_data(blacklist_ans);
	lookup_cachedb(q, &cache_data);
	ptr = cache_data;

	while (ptr != NULL) {
		ans = ptr->data;
		print_answer(ans, stdout, 0);
		if (config.debug)
			print_answer(ans, stderr, 0);
		ptr = ptr->next;
	}

	free_cachedb_data(cache_data);
}

static int rr2answer(const ldns_rr *rr, struct answer *ans)
{
	ldns_buffer *output;
	ldns_rdf *rdf;
	ldns_status res;
	int i, rr_type, rdf_type, rd_count;
	int str_len;
	int data_len;
	struct answer result;
	char *str;

	data_len = 0;
	output = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!output)
		exit(EXIT_FAILURE);

	res = ldns_rdf2buffer_str_dname(output, ldns_rr_owner(rr));
	if (res != LDNS_STATUS_OK) {
		ldns_buffer_free(output);
		return 0;
	}
	str = ldns_buffer2str(output);
	ldns_buffer_free(output);
	if (!str)
		exit(EXIT_FAILURE);

	/* Don't manage to remove dot from name, imagine root domain query '.' */
	str_len = strlen(str);
	if (str_len < sizeof(result.qname) - 1) {
		memcpy(result.qname, str, str_len);
		result.qname[str_len] = 0;
	} else return 0;

	LDNS_FREE(str);

	rd_count = ldns_rr_rd_count(rr);
	for (i = 0; i < rd_count; i++) {

		rdf = ldns_rr_rdf(rr, i);
		output = ldns_buffer_new(LDNS_MAX_PACKETLEN);

		switch ((rdf_type = ldns_rdf_get_type(rdf))) {
			case LDNS_RDF_TYPE_A:
				res = ldns_rdf2buffer_str_a(output, rdf);
				break;
			case LDNS_RDF_TYPE_AAAA:
				res = ldns_rdf2buffer_str_aaaa(output, rdf);
				break;
			case LDNS_RDF_TYPE_DNAME:
				res = ldns_rdf2buffer_str_dname(output, rdf);
				break;
			case LDNS_RDF_TYPE_INT8:
				res = ldns_rdf2buffer_str_int8(output, rdf);
				break;
			case LDNS_RDF_TYPE_INT16:
				res = ldns_rdf2buffer_str_int16(output, rdf);
				break;
			case LDNS_RDF_TYPE_INT32:
				res = ldns_rdf2buffer_str_int32(output, rdf);
				break;
			case LDNS_RDF_TYPE_PERIOD:
				res = ldns_rdf2buffer_str_period(output, rdf);
				break;
			case LDNS_RDF_TYPE_STR:
				res = ldns_rdf2buffer_str_str(output, rdf);
				break;
			default:
				res = LDNS_STATUS_OK + 1;
		}

		if (res != LDNS_STATUS_OK) {
			ldns_buffer_free(output);
			return 0;
		}

		rr_type = ldns_rr_get_type(rr);
		result.qtype = rr_type;

		/* MX data doesn't need the MX priority */
		if (i == 0 && rr_type == LDNS_RR_TYPE_MX) {
			result.mx_code = ldns_read_uint16(ldns_rdf_data(rdf));
			ldns_buffer_free(output);
			continue;
		}

		str = ldns_buffer2str(output);
		str_len = strlen(str);

		if (rdf_type == LDNS_RDF_TYPE_DNAME && str_len > 1)
			str_len--;

		if (data_len + str_len < sizeof(result.data) - 1) {
			memcpy(result.data + data_len, str, str_len);
			data_len += str_len;
		}

		/* Append space separator for each rdf data */
		if ((i < rd_count - 1) && (data_len + 1 < sizeof(result.data) - 1)) {
			memcpy(result.data + data_len, " ", 1);
			data_len++;
		}

		LDNS_FREE(str);
		ldns_buffer_free(output);
	}

	result.data[data_len] = 0;
	result.ttl = ldns_rr_ttl(rr);

	*ans = result;

	return rd_count;
}

static int rr_type[7] = {
	RR_TYPE_A,
	RR_TYPE_AAAA,
	RR_TYPE_SOA,
	RR_TYPE_CNAME,
	RR_TYPE_MX,
	RR_TYPE_NS,
	RR_TYPE_TXT
};

int sort_cachedb_func(const void *a, const void *b)
{
	return ((struct answer*)a)->qtype - ((struct answer*)b)->qtype;
}

static int process_result(const ldns_pkt *pkt, queue_t **result)
{
	queue_t *data = NULL;
	ldns_rr_list *list;
	ldns_rr *rr;
	struct answer *ans;
	int type, i, nrr;
	int retval = 0;

	for (type = 0; type < 7; type++) {

		list = ldns_pkt_rr_list_by_type(pkt, rr_type[type],
						LDNS_SECTION_ANSWER);
		if (!list)
			continue;

		nrr = ldns_rr_list_rr_count(list);
		/* ldns_rr_list_sort(list); */

		for (i = 0; i < nrr; i++) {

			rr = ldns_rr_list_rr(list, i);

			ans = xmalloc(sizeof(struct answer));
			if (!rr2answer(rr, ans)) {
				free(ans);
				continue;
			}

			data = queue_prepend(data, ans);
		}

		retval += nrr;
		ldns_rr_list_deep_free(list);
	}

	if (retval > 0)
		*result = data;

	return retval;
}

int do_query(const struct query *q)
{
	queue_t *data, *ptr;
	struct answer *ans;
	struct timespec start, end, tm, diff, fdiff;
	struct log log;
	struct filter_info fi;
	int result, rcode;
	ldns_rdf *rdf;
	ldns_pkt *pkt;


	if (config.filter) {
		result = 0;

		/*
		 * We don't need to search filtered domain on every record,
		 * PowerDNS below version 3 (eg. 2.9.22) query ANY record 
		 * first, while version 3 is SOA record.
		 */
		if (q->qtype_id == RR_TYPE_ANY || q->qtype_id == RR_TYPE_SOA)
			result = search_blacklist(q, &data, &fi, &fdiff);

		if (result > 0) {
			if (q->qtype_id == RR_TYPE_A || q->qtype_id == RR_TYPE_ANY) {
				ptr = data;
				while (ptr) {
					ans = ptr->data;
					print_answer(ans, stdout, 0);
					if (config.debug)
						print_answer(ans, stderr, 0);
					ptr = ptr->next;
				}
			} else if (q->qtype_id == RR_TYPE_SOA) {
				ans = data->data;
				print_answer(ans, stdout, 0);
				if (config.debug)
					print_answer(ans, stderr, 0);
			}

			if (config.log) {
				log.qtime = 0;
				log.ftime = 
				log.blacklist = 1;
				log.exist = 1;
				log.status = 0;
				log.qtype = q->qtype_id;
				log.reqtime = time(NULL);
				sprintf(log.qname, "%s", q->qname);
				sprintf(log.remote, "%s", q->remote_ip);
				insert_log(&log);
				write_log(&log);
			}

			free_cachedb_data(data);

			return 1;
		}
	}


	result = lookup_cachedb(q, &data);
	if (result > 0) {
		ptr = data;
		while (ptr != NULL) {
			ans = ptr->data;
			print_answer(ans, stdout, 0);
			if (config.debug)
				print_answer(ans, stderr, 1);
			ptr = ptr->next;
		}
		free_cachedb_data(data);
		return 1;
	} else if (result < 0)
		return 1;

	init_resolver();

	rdf = ldns_dname_new_frm_str(q->qname);
	if (!rdf) {
		if (config.debug)
			fprintf(stderr, "<< invalid name: '%s' >>\n", q->qname);
		return 0;
	}

	if (config.debug || config.log)
		clock_gettime(CLOCK_REALTIME, &start);

	pkt = ldns_resolver_query(resolver, rdf,
			          LDNS_RR_TYPE_ANY, 
				  LDNS_RR_CLASS_IN, 
				  LDNS_RD);

	if (config.debug || config.log)
		clock_gettime(CLOCK_REALTIME, &end);

	clock_gettime(CLOCK_MONOTONIC, &tm);

	ldns_rdf_deep_free(rdf);
	if (!pkt) {
		if (config.debug)
			fprintf(stderr, "<< resolve fail: %s >>\n", q->qname);
		return 0;
	}

	rcode = ldns_pkt_get_rcode(pkt);
	if (rcode == LDNS_RCODE_NOERROR) {

		result = process_result(pkt, &data);

		if (result > 0) {
			clear_cachedb(q);
			// sort_cachedb(data);
			insert_cachedb(q, data, tm);
		}

		if (config.debug) {
			diff = ts_diff(&start, &end);
			fprintf(stderr, "<< %s: %i records, resolved in %li ms >>\n", 
				q->qname, result, ts2ms(&diff));
		}

		if (result > 0) {
			ptr = data;
			while (ptr) {
				ans = ptr->data;
				if (ans->qtype == q->qtype_id ||
				    q->qtype_id == RR_TYPE_ANY) {
					print_answer(ans, stdout, 0);
					if (config.debug)
						print_answer(ans, stderr, 0);
				}
				ptr = ptr->next;
			}

			free_cachedb_data(data);
		}
	}

	if (rcode != LDNS_RCODE_NOERROR && config.debug)
		fprintf(stderr, "<< %s: rcode: %i >>\n", q->qname, rcode);

	ldns_pkt_free(pkt);
	destroy_resolver();

	if (config.log) {
		diff = ts_diff(&start, &end);
		log.reqtime = start.tv_sec;
		log.qtime = ((double) diff.tv_sec * NSEC_PER_SEC + 
				diff.tv_nsec) / USEC_PER_SEC;
		log.blacklist = 0;
		log.exist = rcode == LDNS_RCODE_NOERROR ? 1 : 0;
		log.status = rcode;
		log.qtype = q->qtype_id;
		sprintf(log.qname, "%s", q->qname);
		sprintf(log.remote, "%s", q->remote_ip);
		insert_log(&log);
		write_log(&log);
	}

	return 0;
}

void set_dns_type(const char *qtype, struct query *q)
{
	if (!strcmp(qtype, "ANY"))
		q->qtype_id = RR_TYPE_ANY;
	else if (!strcmp(qtype, "A"))
		q->qtype_id = RR_TYPE_A;
	else if (!strcmp(qtype, "AAAA"))
		q->qtype_id = RR_TYPE_AAAA;
	else if (!strcmp(qtype, "SOA"))
		q->qtype_id = RR_TYPE_SOA;
	else if (!strcmp(qtype, "NS"))
		q->qtype_id = RR_TYPE_NS;
	else if (!strcmp(qtype, "MX"))
		q->qtype_id = RR_TYPE_MX;
	else if (!strcmp(qtype, "CNAME"))
		q->qtype_id = RR_TYPE_CNAME;
	else
		q->qtype_id = RR_TYPE_UNDEFINED;
}

int parse_query(char *data, struct query *q)
{
	char *ptr = data;
	char *tmp, *type;

	/* Query type */
	if (!(tmp = strchr(ptr, '\t')))
		return 0;
	if (!strncmp("Q", ptr, tmp - ptr))
		q->type_id = TYPE_ID_Q;
	else if (!strncmp("AXFR", ptr, tmp - ptr)) {
		q->type_id = TYPE_ID_AXFR;
		return 1;
	} else
		return 0;

	/* 
	 * Domain name, PowerDNS doesn't give a '.' for root domain, 
	 * so we manually detect it :(
	 */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (*ptr == '\t')
		sprintf(q->qname, ".");
	else {
		if (!(tmp = strchr(ptr, '\t')))
			return 0;
		snprintf(q->qname, tmp - ptr + 1, "%s", ptr);
	}

	/* Class, actually always 'IN' type */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (!(tmp = strchr(ptr, '\t')))
		return 0;
	if (strncmp("IN", ptr, tmp - ptr))
		return 0;
	else {
		q->qclass_id = QCLASS_ID_IN;
		snprintf(q->qclass, tmp - ptr + 1, "%s", tmp);
	}

	/* Record type */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (!(tmp = strchr(ptr, '\t')))
		return 0;
	type = xstrndup(ptr, tmp - ptr);
	set_dns_type(type, q);
	sprintf(q->qtype, "%s", type);
	free(type);

	/* ID */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (!(tmp = strchr(ptr, '\t')))
		return 0;
	type = xstrndup(ptr, tmp - ptr);
	q->id = strtol(type, NULL, 10);
	free(type);

	/* Remote IP */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	sprintf(q->remote_ip, "%s", ptr);

	return 1;
}

int read_config(void)
{
	GKeyFile *key = g_key_file_new ();
	char *host, *database, *username, *password, *cache_host, *log_database;
	char *landing_page;
	int ret;

	host = database = username = password = cache_host = log_database = NULL;
	ret = g_key_file_load_from_file(key, CONFIG_FILE, G_KEY_FILE_NONE, NULL);
	if (ret == 0) goto err;

	host = g_key_file_get_string(key, "config", "host", NULL);
	if (host == NULL) goto err;
	database = g_key_file_get_string(key, "config", "database", NULL);
	if (database == NULL) goto err;
	username = g_key_file_get_string(key, "config", "username", NULL);
	if (username == NULL) goto err;
	password = g_key_file_get_string(key, "config", "password", NULL);
	if (password == NULL) goto err;
	cache_host = g_key_file_get_string(key, "config", "cache-host", NULL);
	if (cache_host == NULL) goto err;
	log_database = g_key_file_get_string(key, "config", "log-database", NULL);
	if (log_database == NULL) goto err;
	landing_page = g_key_file_get_string(key, "config", "landing-page", NULL);
	if (landing_page == NULL) goto err;

	config.port = g_key_file_get_integer(key, "config", "port", NULL);
	config.cache_port = g_key_file_get_integer(key, "config", "cache-port", NULL);
	config.filter = g_key_file_get_boolean(key, "config", "filter", NULL);
	config.log = g_key_file_get_boolean(key, "config", "log", NULL);
	config.debug = g_key_file_get_boolean(key, "config", "debug", NULL);
	g_key_file_free(key);

	config.host = host;
	config.database = database;
	config.username = username;
	config.password = password;
	config.cache_host = cache_host;
	config.log_database = log_database;
	config.landing_page = landing_page;

	return 1;

err:
	g_key_file_free(key);
	if (host != NULL) g_free(host);
	if (database != NULL) g_free(database);
	if (username != NULL) g_free(username);
	if (cache_host != NULL) g_free(cache_host);
	if (log_database != NULL) g_free(log_database);

	return 0;
}

#if DB_BACKEND == MYSQLS
static inline int connect_database_mysql(unsigned int timeout)
{
	int ret;
	MYSQL *ptr;

	if ((my_conn = mysql_init(0)) == NULL)
		return 0;

	ret = mysql_options(my_conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	if (ret == 0) {
		/* CLIENT_MULTI_RESULTS is flag for stored procedure call */
		ptr = mysql_real_connect(my_conn, config.host, config.username, 
					config.password, config.database,
					config.port, NULL, CLIENT_MULTI_RESULTS);
		if (ptr == NULL) {
			mysql_close(my_conn);
			return 0;
		}
	}

	return 1;
}
#endif

#if DB_BACKEND == PGSQLS
static inline int connect_database_pgsql(unsigned int timeout)
{
	char *cmd;
	int status;

	cmd = g_strdup_printf("hostaddr=%s port=%i dbname=%s user=%s password=%s "
			      "connect_timeout=%i", config.host, config.port,
			      config.database, config.username, config.password,
			      timeout);
	pg_conn = PQconnectdb(cmd);
	status = PQstatus (pg_conn);
	g_free(cmd);

	if (status == CONNECTION_OK)
		return 1;
	else
		return 0;
}
#endif

int connect_database(unsigned int timeout)
{
	int ret;
#if DB_BACKEND == MYSQLS
	ret = connect_database_mysql(timeout);
#elif DB_BACKEND == PGSQLS
	ret = connect_database_pgsql(timeout);
#endif
	if (ret == 0 && config.debug)
		fprintf(stderr, "<< could not connect to db >>\n");
	return ret;
}

static void close_database(void)
{
#if DB_BACKEND == MYSQLS
	mysql_close(my_conn);
#elif DB_BACKEND == PGSQLS
	PQfinish(pg_conn);
#endif
}

#if DB_BACKEND == MYSQLS
static int search_blacklist(const struct query *q, queue_t **blacklist, 
		struct filter_info *fi, struct timespec *diff)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	char *cmd;
	int ret, num_rows, num_fields;
	unsigned long is_block_retval, client_id;
	struct answer *ans;
	struct timespec start, end;
	queue_t *data = NULL;

	clock_gettime(CLOCK_REALTIME, &start);
/*
	ret = lookup_filter_cache(q, fi);
	if (ret) {
		if (config.debug)
			fprintf(stderr, "<< %s: filter cache hits >>\n", __func__);
		clock_gettime(CLOCK_REALTIME, &end);
		*diff = ts_diff(&start, &end);
		if (fi->status)
			goto block;
		else
			return 0;
	}
*/

	if (connect_database(3) == 0)
		exit(EXIT_FAILURE);

	cmd = sqlite3_mprintf("call is_block('%q', '%q')", q->remote_ip, q->qname);

	if (config.debug)
		fprintf(stderr, "<< %s >>\n", cmd);
	ret = mysql_query(my_conn, cmd);

	clock_gettime(CLOCK_REALTIME, &end);
	*diff = ts_diff(&start, &end);

	sqlite3_free(cmd);
	if (ret) {
		fprintf(stderr, "<< %s: sql query failed >>\n", __func__);
		close_database();
		return -1;
	}

	res = mysql_store_result(my_conn);
	if (!res) {
		close_database();
		return 0;
	}

	num_rows = mysql_num_rows(res);
	if (num_rows <= 0) {
		close_database();
		return 0;
	}

	num_fields = mysql_num_fields(res);
	if (num_fields < 3) {
		if (config.debug)
			fprintf(stderr, "<< %s: only return %i fields, "
				"expected 3 fields >>\n", __func__, num_fields);
		mysql_free_result(res);
		close_database();
		return -1;
	}

	row = mysql_fetch_row(res);
	is_block_retval = *row ? strtoul (*row, NULL, 10) : 0;
	client_id = row[2] ? strtoul (row[2], NULL, 10) : 0;

	if (config.debug)
		fprintf(stderr, "<< %s: retval: %lu >>\n", __func__, is_block_retval);

	mysql_free_result(res);
	close_database();

	/* No blocking */
	fi->id = client_id;
	if (is_block_retval == 0UL) {
		fi->status = 0;
		return 0;
	} else
		fi->status = 1;

	/* insert_filter_cache(q, fi); */

block:
	/* Build A and SOA record, PowerDNS need at least SOA 
	 * and A record to make query answered correctly.
	 */

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, config.landing_page);
	ans->qtype = RR_TYPE_A;
	ans->ttl = 3600;

	data = queue_prepend(data, ans);

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, "ns1.amaladns.com dns.amala.net "
	       "2011052500 28800 7200 604800 86400");
	ans->qtype = RR_TYPE_SOA;
	ans->ttl = 3600;

	data = queue_prepend(data, ans);

	if (config.debug)
		fprintf(stderr, "<< %s: record found >>\n", q->qname);;

	*blacklist = data;

	return num_rows;
}
#endif

#if DB_BACKEND == PGSQLS
static int search_blacklist(const struct query *q, queue_t **blacklist, 
		struct filter_info *fi, struct timespec *diff)
{
	PGresult *res;
	struct answer *ans;
	struct timespec start, end;
	queue_t *data = NULL;
	char *tmp;
	int ret;

	ret = lookup_filter_cache(q, fi);
	if (ret == 1 && fi->status)
		goto block;

	clock_gettime(CLOCK_REALTIME, &start);
	if (connect_database(3) == 0)
		return 0;

	tmp = g_strdup_printf("SELECT check_filter_status('%s', '%s')",
			      q->qname, q->remote_ip);
	res = PQexec(pg_conn, tmp);
	clock_gettime(CLOCK_REALTIME, &end);
	*diff = ts_diff(&start, &end);
	g_free(tmp);

	ret = PQresultStatus(res);
	if (ret != PGRES_TUPLES_OK) {
		PQclear(res);
		close_database();
		if (config.debug)
			fprintf(stderr, "<< %s: sql query failed >>\n", __func__);
		return -1;
	}

	if (PQntuples(res) == 0) {
		PQclear(res);
		close_database();
		if (config.debug)
			fprintf(stderr, "<< %s: invalid query returns >>\n", __func__);
	}

	tmp = PQgetvalue(res, 0, 0);
	PQclear(res);
	close_database();

	if (tmp == NULL)
		return 0;

	ret = strtol(tmp, NULL, 10);
	fi->status = ret == 2 ? 0 : 1;
	fi->id = 0;
	insert_filter_cache(q, fi);

	if (ret != 2)
		return 0;

block:

	/* Build A and SOA record, PowerDNS need at least SOA 
	 * and A record to make query answered correctly.
	 */

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, config.landing_page);
	ans->qtype = RR_TYPE_A;
	ans->ttl = 3600;

	data = queue_prepend(data, ans);

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, "ns1.kdns.com dns-admin.kdns.com "
	       "2011101100 7200 1800 1209600 300");
	ans->qtype = RR_TYPE_SOA;
	ans->ttl = 3600;

	data = queue_prepend(data, ans);

	if (config.debug)
		fprintf(stderr, "<< %s: record found >>\n", q->qname);

	*blacklist = data;

	return 1;
}
#endif

static int insert_blacklist_data(const struct answer *ans)
{
	char *cmd;
	int ret;

	cmd = sqlite3_mprintf("INSERT INTO cache VALUES(NULL, '%q', %i, %i, "
				"'%q', %i, '%q')", ans->qname, RR_TYPE_A, 3600,
				"", 0, ans->data);
	ret = sqlite3_exec(cachedb, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	if (ret != SQLITE_OK) return 0;

	cmd = sqlite3_mprintf("INSERT INTO cache VALUES(NULL, '%q', %i, %i, "
				"'%q', %i, '%q')", ans->qname, RR_TYPE_SOA, 3600,
				"", 0, "ns1.amaladns.com dns.amala.net "
				"2011052500 28800 7200 604800 86400");
	ret = sqlite3_exec(cachedb, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	if (ret != SQLITE_OK) return 0;

	cmd = sqlite3_mprintf("INSERT INTO cache VALUES(NULL, '%q', %i, %i, "
				"'%q', %i, '%q')", ans->qname, RR_TYPE_NS, 3600,
				"", 0, "ns1.amaladns.com");
	ret = sqlite3_exec(cachedb, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	if (ret != SQLITE_OK) return 0;

	cmd = sqlite3_mprintf("INSERT INTO cache VALUES(NULL, '%q', %i, %i, "
				"'%q', %i, '%q')", ans->qname, RR_TYPE_MX, 3600,
				"", 0, "mail.amaladns.com");
	ret = sqlite3_exec(cachedb, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	if (ret != SQLITE_OK) return 0;

	cmd = sqlite3_mprintf("INSERT INTO cache VALUES(NULL, '%q', %i, %i, "
				"'%q', %i, '%q')", ans->qname, RR_TYPE_TXT, 3600,
				"", 0, "AmalaDNS by LINKIT360");
	ret = sqlite3_exec(cachedb, cmd, NULL, NULL, NULL);
	sqlite3_free(cmd);
	return 1;
}

void init_cachedb(void)
{
	cachedb_ctx = redisConnect(config.cache_host, config.cache_port);

	if (cachedb_ctx->err) {

		fprintf(stderr, "<< could not initialize cachedb: %s >>\n", 
			cachedb_ctx->errstr);
		exit(EXIT_FAILURE);
	}

#if 0
	if (config.debug)
		fprintf(stderr, "<< %s: connected to %s:%i >>\n",
			__func__, config.cache_host, config.cache_port);
#endif
}

void destroy_cachedb(void)
{
	redisFree(cachedb_ctx);
}

#if 0
/*
 * Set expiration on list specific keys, expiration must be set 
 * after all records data has been pushed.
 */
static void expire_cachedb_records(const struct query *q, const struct answer *a,
				   unsigned int ttl)
{
	int i;
	redisReply *reply;

	for (i = 0; i < 5; i++) {
		reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s:%s:%s %li",
				     KEY_PREFIX, q->qname, rr2str(a->qtype), 
				     field_name[i], ttl);

		if (!reply)
			cachedb_error();
		freeReplyObject(reply);
	}

	reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s:%s %li",
			     KEY_PREFIX, q->qname, rr2str(a->qtype), ttl);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);
}

/* Set qname counter key expiration */
static void expire_cachedb_count(const struct query *q, unsigned int ttl)
{
	redisReply *reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s %li",
					 KEY_PREFIX, q->qname, ttl);

	if (!reply)
		cachedb_error();

	freeReplyObject(reply);
}
#endif

/**
 * Insert database query result into cache that will be used for next 
 * query, but cached. This will keep until given TTL is expired then 
 * new database query requested for the next cache, and so on.
 */
static void insert_filter_cache(const struct query *q, const struct filter_info *info)
{
	redisReply *reply;

	init_cachedb();

	reply = redisCommand(cachedb_ctx, "DEL %s:filter:%s:%s",
			     KEY_PREFIX, q->remote_ip, q->qname);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "RPUSH %s:filter:%s:%s %i",
			     KEY_PREFIX, q->remote_ip, q->qname, info->status);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "RPUSH %s:filter:%s:%s %lu",
			     KEY_PREFIX, q->remote_ip, q->qname, info->id);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "EXPIRE %s:filter:%s:%s %i",
			     KEY_PREFIX, q->remote_ip, q->qname, 180);

	destroy_cachedb();
}

/**
 * Lookup for filter in cache.
 * Returns: 1 if found, filter information will be filled in @info.
 *          0 if not found.
 */
static int lookup_filter_cache(const struct query *q, struct filter_info *info)
{
	redisReply *reply;
	int retval = 0;

	init_cachedb();

	reply = redisCommand(cachedb_ctx, "LRANGE %s:filter:%s:%s 0 -1",
			     KEY_PREFIX, q->remote_ip, q->qname);
	if (!reply)
		cachedb_error();


	if (reply->type == REDIS_REPLY_ARRAY)
		if (reply->elements == 2) {
			info->status = strtol(reply->element[0]->str, NULL, 10);
			info->id = strtoul(reply->element[1]->str, NULL, 10);
			retval = 1;
		}

	freeReplyObject(reply);
	destroy_cachedb();

	return retval;
}

static const char * const field_name[5] = {
	"qname", "type", "ttl", "mxcode", "data"
};

static const char * const type_name[7] = {
	"A", "AAAA", "SOA", "NS", "MX", "CNAME", "TXT"
};

/* 
 * Assigning different ttl expiration for each key is unsafe, on old 
 * Redis version, inserting data to list's key that has expiration 
 * will remove all previous data. Also happen with INCR key, value 
 * will be set to 1, so don't set expiration for list or INCR key 
 * here, but no problem for set.
 *
 * Key expiration value determined by finding the lowest ttl, then
 * double the value.
 */
static void insert_cachedb(const struct query *q, queue_t *data, struct timespec ts)
{
	redisReply *reply;
	queue_t *ptr = data;
	struct answer *a;
	const char *type_str;
	unsigned expiration = 0, len = 0;
	int i;

	init_cachedb();

	/* Find the lowest ttl */
	while (ptr) {
		a = ptr->data;
		if (len == 0)
			expiration = a->ttl;
		expiration = expiration > a->ttl ? a->ttl : expiration;
		ptr = ptr->next;
		len++;
	}

	expiration <<= 1;

	ptr = data;
	while (ptr) {

		a = ptr->data;
		type_str = rr2str(a->qtype);

		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s:%s:qname %s", 
				     KEY_PREFIX, q->qname, type_str, a->qname);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s:%s:type %i", 
				     KEY_PREFIX, q->qname, type_str, a->qtype);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s:%s:ttl %u", 
				     KEY_PREFIX, q->qname, type_str, a->ttl);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s:%s:mxcode %i", 
				     KEY_PREFIX, q->qname, type_str, a->mx_code);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		/* Binary mode for data list */
		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s:%s:data %b", KEY_PREFIX, 
				     q->qname, type_str, a->data, strlen(a->data));
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		reply = redisCommand(cachedb_ctx, "INCR %s:%s:%s", 
				     KEY_PREFIX, q->qname, type_str);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		if (a->qtype == RR_TYPE_NS || a->qtype == RR_TYPE_MX) {
			reply = redisCommand(cachedb_ctx, "SET %s:NSMX:%s %s",
					     KEY_PREFIX, a->data, q->qname);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);

			reply = redisCommand(cachedb_ctx, "EXPIRE %s:NSMX:%s %li", 
					     KEY_PREFIX, a->data, expiration);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}

		ptr = ptr->next;
	}

	/* Set cache's insert time */
	reply = redisCommand(cachedb_ctx, "SET %s:%s:time %li", 
			     KEY_PREFIX, q->qname, ts.tv_sec);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s:time %li", 
			     KEY_PREFIX, q->qname, expiration);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	/*
	 * Set expiration on list specific keys, expiration must be set 
	 * after all records's data has been pushed.
	 */
	ptr = data;
	while (ptr) {
		a = ptr->data;
		for (i = 0; i < 5; i++) {
			reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s:%s:%s %li",
					     KEY_PREFIX, q->qname, rr2str(a->qtype), 
					     field_name[i], expiration);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}

		reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s:%s %li",
				     KEY_PREFIX, q->qname, rr2str(a->qtype), expiration);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		ptr = ptr->next;
	}

	/* Set qname counter and its expiration */
	reply = redisCommand(cachedb_ctx, "SET %s:%s %u", KEY_PREFIX, q->qname, len);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s %li",
			     KEY_PREFIX, q->qname, expiration);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	destroy_cachedb();
}

void free_cachedb_data(queue_t *data)
{
	queue_t *ptr = data;

	while (ptr) {
		free(ptr->data);
		free(ptr);
		ptr = ptr->next;
	}
}

static int lookup_a_record(const struct query *q)
{
	redisReply *reply;
	int retval;

	reply = redisCommand(cachedb_ctx, "EXISTS %s:NSMX:%s", KEY_PREFIX, q->qname);

	if (!reply)
		cachedb_error();

	retval = reply->integer;

	freeReplyObject(reply);

	return retval;
}

static void clear_cachedb(const struct query *q)
{
	redisReply *reply;
	int i, j;

	init_cachedb();

	for (i = 0; i < 7; i++) {
		for (j = 0; j < 5; j++) {
			reply = redisCommand(cachedb_ctx, "DEL %s:%s:%s:%s",
					     KEY_PREFIX, q->qname, type_name[i],
					     field_name[j]);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}

		reply = redisCommand(cachedb_ctx, "DEL %s:%s:%s",
				     KEY_PREFIX, q->qname, type_name[i]);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);
	}

	reply = redisCommand(cachedb_ctx, "DEL %s:%s:time", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "DEL %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	destroy_cachedb();
}

/*
 * Search for records in cache.
 *
 * Returns:
 * -2: MX/NS A record query.
 * -1: Record was not found, but other records exist.
 *  0: Records was not found.
 *  More than 0: Records was found.
 */
int lookup_cachedb(const struct query *q, queue_t **res)
{
	queue_t *data;
	queue_t *ptr;
	int nrecords, n, i;
	unsigned ttl, tmp;
	long tm;
	struct answer *ans;
	struct timespec ts;
	redisReply *reply[5];

	init_cachedb();

	/* Determine how many name's records was cached */

	*reply = redisCommand(cachedb_ctx, "GET %s:%s", KEY_PREFIX, q->qname);
	if (*reply == NULL)
		cachedb_error();

	if ((*reply)->type == REDIS_REPLY_NIL)
		nrecords = 0;
	else
		nrecords = atoi((*reply)->str);

	freeReplyObject(*reply);

	/* n < 0, possible MX/NS record for query */


	*reply = redisCommand(cachedb_ctx, "GET %s:%s:%s", 
			      KEY_PREFIX, q->qname, rr2str(q->qtype_id));

	if (*reply == NULL)
		cachedb_error();

	if ((*reply)->type == REDIS_REPLY_NIL)
		n = 0;
	else
		n = atoi((*reply)->str);

	freeReplyObject(*reply);

	if (config.debug && (nrecords > 0 || n > 0)) {
		if (q->qtype_id == RR_TYPE_ANY)
			fprintf(stderr, "<< %s: cache hits: %i records >>\n",
				q->qname, nrecords);
		else
			fprintf(stderr, "<< %s: cache hits: %i/%i records >>\n",
				q->qname, nrecords, n);
	}

	if (n <= 0) {
		/* Search for possible MX/NS record A or AAAA query */
		if (q->qtype_id == RR_TYPE_A) {
			n = lookup_a_record(q);
			if (n) {
				destroy_cachedb();
				return -2;
			}
			if (nrecords == 0 && n == 0) {
				destroy_cachedb();
				return 0;
			}
			if (nrecords > 0 && n == 0) {
				destroy_cachedb();
				return -1;
			}
		} else if (q->qtype_id == RR_TYPE_ANY) {
			if (nrecords == 0) {
				destroy_cachedb();
				return 0;
			}
		} else {
			if (nrecords == 0 && n == 0) {
				destroy_cachedb();
				return 0;
			}
			if (nrecords > 0 && n == 0) {
				destroy_cachedb();
				return -1;
			}
		}
	}

	nrecords = n;
	ttl = 86400;
	data = NULL;

	/* Iterate over records ttl's field to determine lowest ttl value */
	for (i = 0; i < 7; i++) {
		*reply = redisCommand(cachedb_ctx, "LRANGE %s:%s:%s:%s 0 -1",
				      KEY_PREFIX, q->qname, type_name[i], 
				      field_name[2]);
		if (*reply == NULL)
			cachedb_error();

		for (n = 0; n < reply[0]->elements; n++) {
			tmp = atol(reply[0]->element[n]->str);
			ttl = ttl > tmp ? tmp : ttl;
		}

		freeReplyObject(*reply);
	}

	/* Insert queue's data with cache records */
	if (q->qtype_id == RR_TYPE_ANY) {

		for (i = 0; i < 7; i++) {
			for (n = 0; n < 5; n++) {
				reply[n] = redisCommand(cachedb_ctx, "LRANGE "
							"%s:%s:%s:%s 0 -1",
							KEY_PREFIX, q->qname,
							type_name[i], field_name[n]);
				if (!reply[n])
					cachedb_error();
			}

			/* Iterate and insert each record type to list */
			for (n = 0; n < reply[0]->elements; n++) {
				ans = xmalloc(sizeof(struct answer));
				strcpy(ans->qname, reply[0]->element[n]->str);
				ans->qtype = atoi(reply[1]->element[n]->str);
				ans->ttl = atol(reply[2]->element[n]->str);
				ans->mx_code = atoi(reply[3]->element[n]->str);
				strcpy(ans->data, reply[4]->element[n]->str);
				data = queue_prepend(data, ans);
			}

			for (n = 0; n < 5; n++)
				freeReplyObject(reply[n]);
		}

	} else {
		for (n = 0; n < 5; n++) {
			reply[n] = redisCommand(cachedb_ctx, "LRANGE %s:%s:%s:%s 0 -1",
						KEY_PREFIX, q->qname,
						rr2str(q->qtype_id), field_name[n]);
			if (!reply[n])
				cachedb_error();
		}

		for (n = 0; n < reply[0]->elements; n++) {
			ans = xmalloc(sizeof(struct answer));
			strcpy(ans->qname, reply[0]->element[n]->str);
			ans->qtype = atoi(reply[1]->element[n]->str);
			ans->ttl = atol(reply[2]->element[n]->str);
			ans->mx_code = atoi(reply[3]->element[n]->str);
			strcpy(ans->data, reply[4]->element[n]->str);
			data = queue_prepend(data, ans);
		}

		for (n = 0; n < 5; n++)
			freeReplyObject(reply[n]);
	}

	*reply = redisCommand(cachedb_ctx, "GET %s:%s:time", KEY_PREFIX, q->qname);
	if (*reply == NULL)
		cachedb_error();

	tm = atol((*reply)->str);

	freeReplyObject(*reply);

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec - tm <= ttl) {
		ptr = data;
		while (ptr) {
			struct answer *a = ptr->data;
			a->ttl -= ts.tv_sec - tm;
			ptr = ptr->next;
		}
		if (config.debug)
			fprintf(stderr, "<< %s: expire in %li s >>\n", 
				q->qname, ttl - (ts.tv_sec - tm));
	} else {
		if (config.debug)
			fprintf(stderr, "<< %s: cache was expired, min ttl: "
				"%i s >>\n", q->qname, ttl);
		free_cachedb_data(data);
		destroy_cachedb();
		return 0;
	}

	*res = data;

	destroy_cachedb();

	return 1;
}

int insert_log(const struct log *log)
{
	struct tm *st;
	char *cmd, *reqtime;
	int ret;

	MYSQL *conn;
	MYSQL *ptr;
	unsigned int timeout = 3;

	if ((conn = mysql_init(0)) == NULL) {
		fprintf(stderr, "<< could not initialize logdb >>\n");
		return 0;
	}

	ret = mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	if (ret == 0) {
		ptr = mysql_real_connect(conn, config.host, config.username, 
					config.password, config.log_database,
					config.port, NULL, 0);
		if (ptr == NULL) {
			mysql_close(conn);
			fprintf(stderr, "<< could not connect to logdb >>\n");
			return 0;
		}
	}

	st = localtime(&log->reqtime);
	reqtime = g_strdup_printf("%i-%.2i-%.2i %.2i:%.2i:%.2i", 
				st->tm_year + 1900, st->tm_mon + 1, st->tm_mday,
				st->tm_hour, st->tm_min, st->tm_sec);

	cmd = sqlite3_mprintf("INSERT INTO %i_%.2i VALUES(NULL, '%q', '%q', "
				"'%q', '%q', %i, %i, %i, %i, %i)", st->tm_year + 1900,
				st->tm_mon + 1, reqtime, log->remote, log->qname, 
				type_str(log->qtype), log->qtime, log->ftime,
				log->blacklist, log->exist, log->status);

	ret = mysql_query(conn, cmd);
	g_free(reqtime);
	sqlite3_free(cmd);

	mysql_close(conn);

	if (ret) {
		fprintf(stderr, "<< could not run logdb query >>\n");
		return 0;
	}

	return 1;
}

/*
 * Log format:
 * YYYY-MM-DD_HH:MM:SS ip domain qtime ftime isblock isexist status
 */
int write_log(const struct log *log)
{
	struct tm *st = localtime(&log->reqtime);
	static char date[11], tmp[BUFSIZ], time_string[20];
	int ret;
	FILE *fp;

	sprintf(date, "%i-%.2i-%.2i", st->tm_year + 1900, st->tm_mon + 1, st->tm_mday);
	snprintf(tmp, sizeof(tmp), "%s/cpdns_%s.log", LOG_DIR, date);

	fp = fopen(tmp, "a");
	if (fp == NULL) {
		if (config.debug)
			fprintf(stderr, "<< could not open log file >>\n");
		return 0;
	}

	sprintf(time_string, "%s_%.2i:%.2i:%.2i", date, 
		st->tm_hour, st->tm_min, st->tm_sec);
	ret = snprintf(tmp, sizeof(tmp), "%s %s %s %i %i %i %i %i %i\n", time_string,
		       log->qname, log->remote, log->qtime, log->ftime, log->blacklist,
		       log->exist, log->status, backend_id);

	ret = fwrite(tmp, ret, 1, fp);
	if (ret <= 0)
		if (config.debug)
			fprintf(stderr, "<< could not write log file >>\n");

	fclose(fp);
	return ret;
}

int main(void)
{
	struct query q;
	char buffer[BUFSIZ];
	char tmp_buffer[BUFSIZ];

	set_backend_id();

	if (read_config() == 0) {
		fprintf(stderr, "<< could not parse configuration file >>\n");
		return 1;
	}

	/* Set stdout to unbuffered */
	setvbuf(stdout, 0, _IONBF, 0);

	for (;;) {
		if (fgets(buffer, sizeof buffer, stdin) == NULL)
			return 1;

		if (strncmp(buffer, "HELO\t", 5)) {
			fprintf(stderr, "<< invalid handshake string >>\n");
			fflush(stdin);
			continue;
		}
		break;
	}

	puts("OK\tWelcome");

	for (;;) {
		fflush(stdin);
		if (fgets(buffer, sizeof buffer, stdin) == NULL)
			return 1;

		if (config.debug) {
			memcpy(tmp_buffer, buffer, strlen(buffer));
			tmp_buffer[strlen(buffer) - 1] = 0;
			fprintf(stderr, "%s [ID:%i]\n", tmp_buffer, backend_id);
		}

		if (!parse_query(buffer, &q)) {
			if (config.debug)
				fprintf(stderr, "<< parse failed >>\n");
			goto end;
		}

		/* Sometime PowerDNS ask with asterisk '*' sign, eg '*.com' 
		 * don't have any idea yet so just discard it.
		 */
		if (*q.qname == '*') goto end;

		do_query(&q);

end:
		puts("END");
		if (config.debug)
			fprintf(stderr, "END\n");
	}

	return 0;
}
