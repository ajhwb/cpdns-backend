/*
 * Cool PowerDNS Backend
 *
 * Copyright (C) 2011 - 2012, Ardhan Madras <ajhwb@knac.com>
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
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include <hiredis/hiredis.h>
#include <ldns/ldns.h>
#include <mysql/mysql.h>

#include "queue.h"
#include "keyval.h"
#include "regdom.h"
#include "tld-canon.h"


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

/* FIXME: qname and data field should be in dynamic size */
struct answer {
	int qtype;
	int mx_code;
	unsigned int ttl;
	char qname[256];
	char data[512];
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
	char *log_dir;
	char *redirect_address;
	unsigned short port;
	unsigned short cache_port;
	int filter;
	int log;
	int log_file;
	int debug;
	int use_recursor;
	int redirect_error;
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
static tldnode *tld_node;
static struct config config;
static int backend_id;
static MYSQL *my_conn;


int lookup_cachedb(const struct query*, queue_t**);
static void print_answer(const struct answer*, FILE*, int);
static void clear_cachedb(const struct query*);
void free_cachedb_data(queue_t*);
static int search_blacklist(const struct query*, queue_t**, 
				struct filter_info*, struct timespec*);
static int insert_log(const struct log*);
static int write_log(const struct log*);
static int init_resolver(void);
static void insert_cachedb(const struct query*, queue_t*, struct timespec);
static void close_database(void);
static void insert_filter_cache(const struct query*, const struct filter_info*);
static int lookup_filter_cache(const struct query*, struct filter_info*);
static int str2answer(const char*, struct answer*);
static void init_cachedb(void);
static void destroy_cachedb(void);
static int insert_record(const char*, const char*, queue_t**);


#define cachedb_error() \
do { \
	fprintf(stderr, "<< %s: %s >>\n", __func__, \
		cachedb_ctx->errstr); \
	exit(EXIT_FAILURE); \
} while (0);


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
		memcpy(dst, src, l);
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

static int str2rr(const char *str)
{
	if (!strcmp("ANY", str))
		return RR_TYPE_ANY;
	if (!strcmp("A", str))
		return RR_TYPE_A;
	if (!strcmp("AAAA", str))
		return RR_TYPE_AAAA;
	if (!strcmp("SOA", str))
		return RR_TYPE_SOA;
	if (!strcmp("MX", str))
		return RR_TYPE_MX;
	if (!strcmp("NS", str))
		return RR_TYPE_NS;
	if (!strcmp("CNAME", str))
		return RR_TYPE_CNAME;
	if (!strcmp("TXT", str))
		return RR_TYPE_TXT;
	return RR_TYPE_UNDEFINED;
}

static int init_resolver(void)
{
	ldns_status status;
	const struct timeval tv = { .tv_sec = 1, .tv_usec = 200000 };

	resolver = NULL;

	status = ldns_resolver_new_frm_file(&resolver, NULL);

	if (status != LDNS_STATUS_OK)
		return 0;
	ldns_resolver_set_timeout(resolver, tv);

	return 1;
}

static void destroy_resolver(void)
{
	ldns_resolver_deep_free(resolver);
}

static void init_tldnode(void)
{
	extern char *tldString;

	tld_node = readTldTree(tldString);
	if (!tld_node) {
		fprintf(stderr, "<< could not initialize tldnode >>\n");
		exit(EXIT_FAILURE);
	}
}

static void free_tldnode(void)
{
	freeTldTree(tld_node);
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
	if (str_len > 1)
		str_len--;
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
		} else {
			/* Each data field must start and end with '"' */
			memcpy(result.data, str, sizeof(result.data) - 2);
			result.data[sizeof(result.data) - 2] = '"';
			data_len += sizeof(result.data) - 1;

			if (config.debug)
				fprintf(stderr, "<< %s: data field oversized the "
					"buffer >>\n", __func__);
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

struct resolve_data {
	const ldns_rdf *rdf;
	queue_t **result;
	pthread_mutex_t *mutex;
	int type;
};

void *get_all_record_async_func(void *arg)
{
	ldns_pkt *pkt;
	ldns_rr_list *list;
	ldns_rr *rr;
	queue_t *tmp, *ptr;
	struct answer *ans;
	struct resolve_data *data = arg;
	int nrr, i;

	pkt = ldns_resolver_query(resolver, data->rdf, data->type,
				  LDNS_RR_CLASS_IN, LDNS_RD);
	if (!pkt) {
		fprintf(stderr, "<< %s: resolve fail >>\n", __func__);
		return NULL;
	}

	if (ldns_pkt_get_rcode(pkt) != LDNS_RCODE_NOERROR) {
		ldns_pkt_free(pkt);
		return NULL;
	}

	list = ldns_pkt_rr_list_by_type(pkt, data->type, LDNS_SECTION_ANSWER);
	ldns_pkt_free(pkt);
	if (!list)
		return NULL;

	nrr = ldns_rr_list_rr_count(list);
	if (nrr > 0)
		ldns_rr_list_sort(list);

	tmp = NULL;
	for (i = 0; i < nrr; i++) {
		rr = ldns_rr_list_rr(list, i);
		ans = xmalloc(sizeof(struct answer));
		if (!rr2answer(rr, ans)) {
			free(ans);
			continue;
		}
		tmp = queue_prepend(tmp, ans);
	}

	ldns_rr_list_deep_free(list);

	if (tmp != NULL) {
		pthread_mutex_lock(data->mutex);
		if (*data->result == NULL)
			*data->result = tmp;
		else {
			ptr = queue_last(*data->result);
			ptr->next = tmp;
		}
		pthread_mutex_unlock(data->mutex);
	}
	return NULL;
}

/*
 * Get all record contains in rr_type synchronously, 
 * good speed but take many resources.
 */
int get_all_record_async(const ldns_rdf *rdf, queue_t **result, struct timespec *diff)
{
	size_t ntype = sizeof(rr_type) / sizeof(*rr_type);
	struct resolve_data *data[ntype];
	pthread_t thread[ntype];
	pthread_mutex_t mutex;
	queue_t *tmp_result = NULL;
	struct timespec start, end;
	int type, ret;

	ret = pthread_mutex_init(&mutex, NULL);
	if (ret != 0) {
		fprintf(stderr, "<< %s: could not initialize mutex >>\n", __func__);
		exit(EXIT_FAILURE);
	}

	clock_gettime(CLOCK_REALTIME, &start);

	for (type = 0; type < ntype; type++) {
		data[type] = xmalloc(sizeof(struct resolve_data));
		data[type]->rdf = rdf;
		data[type]->result = &tmp_result;
		data[type]->mutex = &mutex;
		data[type]->type = rr_type[type];

		ret = pthread_create(&thread[type], NULL, 
				     get_all_record_async_func, data[type]);
		if (ret != 0) {
			fprintf(stderr, "<< %s: could not create thread >>\n", __func__);
			exit(EXIT_FAILURE);
		}
	}

	for (type = 0; type < ntype; type++) {
		pthread_join(thread[type], NULL);
		free(data[type]);
	}
	clock_gettime(CLOCK_REALTIME, &end);
	pthread_mutex_destroy(&mutex);

	*diff = ts_diff(&start, &end);
	if (queue_length(tmp_result) > 0)
		*result = tmp_result;

	return LDNS_RCODE_NOERROR;
}

/*
 * Get all record contains in rr_type asynchronously, 
 * use low resources but slow.
 */
int get_all_record_sync(const ldns_rdf *rdf, queue_t **result, struct timespec *diff)
{
	ldns_pkt *pkt;
	queue_t *tmp_result = NULL, *ptr;
	struct timespec start, end;
	int nrecord = 0, type = 0, rcode, ret;

	clock_gettime(CLOCK_REALTIME, &start);

	while (type < sizeof(rr_type) / sizeof(*rr_type)) {
		pkt = ldns_resolver_query(resolver, rdf, rr_type[type],
					  LDNS_RR_CLASS_IN, LDNS_RD);
		if (!pkt) {
			fprintf(stderr, "<< %s: resolve fail\n", __func__);
			return -1;
		}

		rcode = ldns_pkt_get_rcode(pkt);
		if (rcode != LDNS_RCODE_NOERROR) {
			free_cachedb_data(tmp_result);
			return rcode;
		}

		queue_t *tmp = NULL;
		ret = process_result(pkt, &tmp);
		ldns_pkt_free(pkt);
		type++;

		if (ret > 0) {
			nrecord += ret;
			if (!tmp_result)
				tmp_result = tmp;
			else {
				ptr = queue_last(tmp_result);
				ptr->next = tmp;
			}
		}
	}

	clock_gettime(CLOCK_REALTIME, &end);
	*diff = ts_diff(&start, &end);
	if (nrecord > 0)
		*result = tmp_result;

	return rcode;
}

/*
 * do_query:
 * Returns: ldns_enum_plt_rcode enumerations.
 */
int do_query(const struct query *q)
{
	queue_t *data = NULL, *sorted_data = NULL, *ptr;
	struct answer *ans;
	struct timespec start, end, tm, diff, fdiff;
	struct log log;
	struct filter_info fi;
	int result, rcode;
	int qtime = 0;
	int ftime = 0;
	int blacklist = 0;
	long reqtime = time(NULL);
	ldns_rdf *rdf = NULL;
	ldns_pkt *pkt = NULL;

	fdiff = (struct timespec) { .tv_sec = 0, .tv_nsec = 0 };
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

			/*
			 * Depends on version of PowerDNS, it may query for SOA
			 * record first then ANY record, and vice-versa.
			 */
			if ((config.log || config.log_file) 
			    && q->qtype_id == RR_TYPE_SOA) {
				ftime = ts2ms(&fdiff);
				blacklist = 1;
			}
			rcode = LDNS_RCODE_NOERROR;
			goto log;
		}
	}

	ftime = ts2ms(&fdiff);

	if (config.use_recursor && !config.redirect_error) {
		rcode = LDNS_RCODE_NOERROR;
		goto log;
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
		if ((config.log || config.log_file) && q->qtype_id == RR_TYPE_SOA) {
			rcode = LDNS_RCODE_NOERROR;
			goto log;
		}

		return LDNS_RCODE_NOERROR;
	} else if (result == -1) {
		if (config.redirect_error) {
			rcode = LDNS_RCODE_NOERROR;
			goto log;
		}
		return LDNS_RCODE_NOERROR;
	} else if (result == -2)
		return LDNS_RCODE_NOERROR;

	init_resolver();

	rdf = ldns_dname_new_frm_str(q->qname);
	if (!rdf) {
		if (config.debug)
			fprintf(stderr, "<< invalid name: '%s' >>\n", q->qname);

		rcode = LDNS_RCODE_FORMERR;

		if (config.redirect_error) {
			result = insert_record(q->qname, config.redirect_address, &data);
			sorted_data = data;
			goto process;
		}
		goto log;
	}

	if (config.debug || config.log || config.log_file)
		clock_gettime(CLOCK_REALTIME, &start);

	/*
	 * It's always better to query for A record to probe name exisistence,
	 * we should not rely on ANY or SOA query result because a name may
	 * return NXDOMAIN or SERVFAIL for non A record query. 
	 */
	pkt = ldns_resolver_query(resolver, rdf,
			          (config.redirect_error && config.use_recursor) ? 
				  LDNS_RR_TYPE_A : LDNS_RR_TYPE_ANY, 
				  LDNS_RR_CLASS_IN, 
				  LDNS_RD);

	if (config.debug || config.log || config.log_file) {
		clock_gettime(CLOCK_REALTIME, &end);
		diff = ts_diff(&start, &end);
		qtime = ts2ms(&diff);
	}

	clock_gettime(CLOCK_MONOTONIC, &tm);

	if (!pkt) {
		rcode = LDNS_RCODE_SERVFAIL;
		if (config.debug)
			fprintf(stderr, "<< resolve fail: %s >>\n", q->qname);
		if (config.redirect_error) {
			result = insert_record(q->qname, config.redirect_address, &data);
			sorted_data = data;
			goto process;
		} else {
			destroy_resolver();
			ldns_rdf_deep_free(rdf);
			goto log;
		}
	}

	rcode = ldns_pkt_get_rcode(pkt);

	if (config.redirect_error && rcode != LDNS_RCODE_NOERROR) {
		result = insert_record(q->qname, config.redirect_address, &data);
		sorted_data = data;
		goto process;
	}

	if (rcode == LDNS_RCODE_NOERROR) {
		if (config.redirect_error && config.use_recursor)
			result++;
		else
			result = process_result(pkt, &data);

		if (result > 0) {
			clear_cachedb(q);
			sorted_data = queue_sort(data, sort_cachedb_func);
			init_cachedb();
			insert_cachedb(q, sorted_data, tm);
			destroy_cachedb();
		} else {
			if (config.debug)
				fprintf(stderr, "<< %s: has no ANY record >>\n", q->qname);
			get_all_record_async(rdf, &data, &diff);
			result = queue_length(data);
			if (result > 0) {
				sorted_data = queue_sort(data, sort_cachedb_func);
				init_cachedb();
				insert_cachedb(q, sorted_data, tm);
				destroy_cachedb();
			}
		}

		if (config.debug)
			fprintf(stderr, "<< %s: %i records, resolved in %i ms >>\n", q->qname,
				config.redirect_error ? 0 : result, qtime);
process:
		if (result > 0) {
			ptr = sorted_data;
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

	if (rdf)
		ldns_rdf_deep_free(rdf);
	if (pkt)
		ldns_pkt_free(pkt);
	destroy_resolver();

log:
	if ((config.log || config.log_file) && q->qtype_id == RR_TYPE_SOA) {
		log.reqtime = reqtime;
		log.qtime = qtime;
		log.ftime = ftime;
		log.blacklist = blacklist;
		log.exist = rcode == LDNS_RCODE_NOERROR ? 1 : 0;
		log.status = rcode;
		log.qtype = q->qtype_id;
		sprintf(log.qname, "%s", q->qname);
		sprintf(log.remote, "%s", q->remote_ip);
		if (config.log)
			insert_log(&log);
		if (config.log_file)
			write_log(&log);
	}

	if (config.redirect_error)
		return LDNS_RCODE_NOERROR;
	return rcode;
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
	if (tmp - ptr <= 0)
		return 0;
	if (!strncmp("Q", ptr, tmp - ptr))
		q->type_id = TYPE_ID_Q;
	else if (!strncmp("AXFR", ptr, tmp - ptr)) {
		q->type_id = TYPE_ID_AXFR;
		return 0;
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
		if (tmp - ptr <= 0)
			return 0;
		type = xstrndup(ptr, tmp - ptr);
		sprintf(q->qname, "%s", type);
		free(type);
	}

	/* Class, actually always 'IN' type */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (!(tmp = strchr(ptr, '\t')))
		return 0;
	if (tmp - ptr <= 0)
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
	if (tmp - ptr <= 0)
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
	if (tmp - ptr <= 0)
		return 0;
	type = xstrndup(ptr, tmp - ptr);
	q->id = strtol(type, NULL, 10);
	free(type);

	/* Remote IP */
	ptr = ++tmp;
	if (*ptr == '\0')
		return 0;
	if (!(tmp = strchr(ptr, '\n')))
		return 0;
	if (tmp - ptr <= 0)
		return 0;
	snprintf(q->remote_ip, tmp - ptr + 1, "%s", ptr);

	return 1;
}

int read_config(void)
{
	keyval_t *key;
	char *host, *database, *username, *password, *cache_host, 
		*log_database, *log_dir, *landing_page, *redirect_address;

	host = database = username = password = cache_host = log_database = NULL;
	log_dir = redirect_address = NULL;

	key = keyval_new(CONFIG_FILE);
	if (key == NULL) goto err;

	host = keyval_get_string(key, "host");
	if (host == NULL) goto err;
	database = keyval_get_string(key, "database");
	if (database == NULL) goto err;
	username = keyval_get_string(key, "username");
	if (username == NULL) goto err;
	password = keyval_get_string(key, "password");
	if (password == NULL) goto err;
	cache_host = keyval_get_string(key, "cache-host");
	if (cache_host == NULL) goto err;
	log_database = keyval_get_string(key, "log-database");
	if (log_database == NULL) goto err;
	landing_page = keyval_get_string(key, "landing-page");
	if (landing_page == NULL) goto err;
	log_dir = keyval_get_string(key, "log-dir");
	if (log_dir == NULL)
		log_dir = strdup(LOG_DIR);
	redirect_address = keyval_get_string(key, "redirect-error-address");
	if (redirect_address == NULL) goto err;

	config.port = keyval_get_integer(key, "port");
	config.cache_port = keyval_get_integer(key, "cache-port");
	config.filter = keyval_get_boolean(key, "filter");
	config.log = keyval_get_boolean(key, "log");
	config.debug = keyval_get_boolean(key, "debug");
	config.log_file = keyval_get_boolean(key, "log-file");
	config.use_recursor = keyval_get_boolean(key, "use-recursor");
	config.redirect_error = keyval_get_boolean(key, "redirect-error");
	keyval_free(key);

	config.host = host;
	config.database = database;
	config.username = username;
	config.password = password;
	config.cache_host = cache_host;
	config.log_database = log_database;
	config.landing_page = landing_page;
	config.log_dir = log_dir;
	config.redirect_address = redirect_address;

	return 1;

err:
	keyval_free(key);
	if (host != NULL) free(host);
	if (database != NULL) free(database);
	if (username != NULL) free(username);
	if (cache_host != NULL) free(cache_host);
	if (log_database != NULL) free(log_database);
	if (log_dir != NULL) free(log_dir);
	if (redirect_address != NULL) free(redirect_address);

	return 0;
}

static inline int connect_database(unsigned int timeout)
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

static void close_database(void)
{
	mysql_close(my_conn);
}

static int search_blacklist(const struct query *q, queue_t **blacklist, 
		struct filter_info *fi, struct timespec *diff)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	static char cmd[256];
	int ret, num_rows, num_fields;
	unsigned long is_block_retval;
	char *regdom;
	struct answer *ans;
	struct timespec start, end;
	queue_t *data = NULL;

	clock_gettime(CLOCK_REALTIME, &start);
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

	regdom = getRegisteredDomain((char*) q->qname, tld_node);

	clock_gettime(CLOCK_REALTIME, &start);

	if (connect_database(3) == 0)
		exit(EXIT_FAILURE);

	sprintf(cmd, "select check_filter_status('%s', '%s')", 
		regdom ? regdom : q->qname, q->remote_ip);

	ret = mysql_query(my_conn, cmd);

	clock_gettime(CLOCK_REALTIME, &end);
	*diff = ts_diff(&start, &end);
	if (regdom)
		free(regdom);

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
	if (num_fields < 1) {
		if (config.debug)
			fprintf(stderr, "<< %s: expected 1 field >>\n", __func__);
		mysql_free_result(res);
		close_database();
		return -1;
	}

	row = mysql_fetch_row(res);
	is_block_retval = *row ? strtoul (*row, NULL, 10) : 0;

	if (config.debug)
		fprintf(stderr, "<< %s: status: %lu >>\n", __func__, is_block_retval);

	mysql_free_result(res);
	close_database();

	/* No blocking */
	fi->id = 0;
	if (is_block_retval == 2)
		fi->status = 1;
	else
		fi->status = 0;

	insert_filter_cache(q, fi);
	if (!fi->status)
		return 0;

block:
	/* Build A and SOA record, PowerDNS need at least SOA 
	 * and A record to make query answered correctly.
	 */

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, config.landing_page);
	ans->qtype = RR_TYPE_A;
	ans->ttl = 0;

	data = queue_prepend(data, ans);

	ans = xmalloc(sizeof(struct answer));

	strcpy(ans->qname, q->qname);
	strcpy(ans->data, "ns1.kdns.com dns.kdns.com "
	       "2011052500 28800 7200 604800 86400");
	ans->qtype = RR_TYPE_SOA;
	ans->ttl = 3600;

	data = queue_prepend(data, ans);

	if (config.debug)
		fprintf(stderr, "<< %s: record found >>\n", q->qname);;

	*blacklist = data;

	return 1;
}

static void init_cachedb(void)
{
	cachedb_ctx = redisConnect(config.cache_host, config.cache_port);

	if (cachedb_ctx->err) {

		fprintf(stderr, "<< could not initialize cachedb: %s >>\n", 
			cachedb_ctx->errstr);
		exit(EXIT_FAILURE);
	}
}

static void destroy_cachedb(void)
{
	redisFree(cachedb_ctx);
}

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

	reply = redisCommand(cachedb_ctx, "WATCH %s:filter:%s:%s",
			     KEY_PREFIX, q->remote_ip, q->qname);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "MULTI");
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
	freeReplyObject(reply);

	reply = redisCommand(cachedb_ctx, "EXEC");
	if (!reply)
		cachedb_error();
	if (config.debug && reply->type == REDIS_REPLY_NIL)
		fprintf(stderr, "<< %s: exec reply nil, possible due "
			"optimistic locking >>\n", __func__);
	freeReplyObject(reply);

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

void insert_cachedb(const struct query *q, queue_t *data, struct timespec ts)
{
	redisReply *reply;
	queue_t *ptr, *cname_ptr;
	queue_t *cname_list = NULL;
	queue_t *cname_result = NULL;
	struct answer *ans, *cname_ans;
	struct query cname_query;
	static char string[BUFSIZ];
	char *cname_data;
	int value, count = 0;
	int min_ttl = 0;

	reply = redisCommand(cachedb_ctx, "EXISTS %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	value = reply->integer;
	freeReplyObject(reply);
	if (value)
		return;

	/*
	 * If error redirection and recursor are activated, key is only used 
	 * to mark name's existence.
	 */
	if (config.redirect_address && config.use_recursor) {
		reply = redisCommand(cachedb_ctx, "SET %s:%s 1", KEY_PREFIX, q->qname);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s %i",
					KEY_PREFIX, q->qname, 3600);
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);
		return;
	}

	/* Determine minimal ttl for expiration */
	ptr = data;
	while (ptr) {
		ans = ptr->data;
		if (ptr == data)
			min_ttl = ans->ttl;
		else
			min_ttl = min_ttl < ans->ttl ? min_ttl : ans->ttl;
		ptr = ptr->next;
		count++;
	}

	ptr = data;
	while (ptr) {
		ans = ptr->data;
		snprintf(string, sizeof(string), "%s,%s,%i,%i,%s", 
			 ans->qname, rr2str(ans->qtype), ans->ttl, 
			 ans->qtype == RR_TYPE_MX ? ans->mx_code : 0, ans->data);

		reply = redisCommand(cachedb_ctx, "RPUSH %s:%s %b", 
				     KEY_PREFIX, q->qname, string, strlen(string));
		if (!reply)
			cachedb_error();
		freeReplyObject(reply);

		/* Store CNAME data to collect the data's records */
		if (ans->qtype == RR_TYPE_CNAME) {
			cname_data = xstrndup(ans->data, -1);
			cname_list = queue_prepend(cname_list, cname_data);
		}

		/* For NS and MX record */
		if (ans->qtype == RR_TYPE_NS || ans->qtype == RR_TYPE_MX) {
			reply = redisCommand(cachedb_ctx, "SET %s:NSMX:%s %s",
					     KEY_PREFIX, ans->data, q->qname);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);

			/* 
			 * Hack 0 ttl to prevent resolving of a NS/MX name A record
			 * because of early cache expiration (very low or 0 ttl).
	 		 */
			reply = redisCommand(cachedb_ctx, "EXPIRE %s:NSMX:%s %i",
					     KEY_PREFIX, ans->data, 
					     min_ttl <= 0 ? 1 : min_ttl);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}

		ptr = ptr->next;

		/* Also hack list ttl to prevent re-resolving */
		if (!ptr) {
			reply = redisCommand(cachedb_ctx, "EXPIRE %s:%s %i", 
					     KEY_PREFIX, q->qname, 
					     min_ttl <= 0 ? 1 : min_ttl);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}
	}

	/* Collect each CNAME data's records */
	cname_ptr = cname_list;
	while (cname_ptr) {
		ptr = data;
		while (ptr) {
			ans = ptr->data;
			if (!strcmp(ans->qname, (char*) cname_list->data)) {
				cname_ans = xmalloc(sizeof(struct answer));
				memcpy(cname_ans, ans, sizeof(struct answer));
				cname_result = queue_prepend(cname_result, cname_ans);
			}
			ptr = ptr->next;
		}
		cname_ptr = cname_ptr->next;
	}

	if (cname_list)
		free_cachedb_data(cname_list);

	/* Recurse insertion of CNAME data's records */
	cname_ptr = cname_result;
	while (cname_ptr) {
		memcpy(&cname_query, q, sizeof(struct query));
		ans = cname_ptr->data;
		sprintf(cname_query.qname, "%s", ans->qname);

		insert_cachedb(&cname_query, cname_result, ts);
		cname_ptr = cname_ptr->next;
	}

	if (cname_result)
		free_cachedb_data(cname_result);
}

void free_cachedb_data(queue_t *data)
{
	queue_t *ptr = data;
	queue_t *tmp;

	while (ptr) {
		tmp = ptr->next;
		free(ptr->data);
		free(ptr);
		ptr = tmp;
	}
}

static int insert_record(const char *qname, const char *address, queue_t **record_out)
{
	struct answer *ans;
	queue_t *record = NULL;

	ans = xmalloc(sizeof(struct answer));
	strcpy(ans->qname, qname);
	strcpy(ans->data, address);
	ans->qtype = RR_TYPE_A;
	ans->ttl = 0;

	record = queue_prepend(record, ans);

	ans = xmalloc(sizeof(struct answer));
	strcpy(ans->qname, qname);
	strcpy(ans->data, "ns1.kdns.com dns.kdns.com "
	       "2011052500 28800 7200 604800 86400");
	ans->qtype = RR_TYPE_SOA;
	ans->ttl = 3600;

	record = queue_prepend(record, ans);
	*record_out = record;

	return queue_length(record);
}

/*
 * Should only be called by routine that perform init_cachedb() first.
 */
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
	struct answer ans;
	static char cmd_buffer[BUFSIZ];
	int value, i;

	init_cachedb();

	reply = redisCommand(cachedb_ctx, "EXISTS %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	value = reply->integer;
	freeReplyObject(reply);
	if (!value) {
		destroy_cachedb();
		return;
	}

	/* Look for any NS/MX record to delete NSMX key */
	reply = redisCommand(cachedb_ctx, "LRANGE %s:%s 0 -1", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();

	for (i = 0; i < reply->elements; i++) {
		if (!str2answer(reply->element[i]->str, &ans))
			break;
		if (ans.qtype == RR_TYPE_NS || ans.qtype == RR_TYPE_MX) {
			snprintf(cmd_buffer, sizeof(cmd_buffer), "%s:NSMX:%s", 
				 KEY_PREFIX, ans.data);

			reply = redisCommand(cachedb_ctx, "DEL %s", cmd_buffer);
			if (!reply)
				cachedb_error();
			freeReplyObject(reply);
		}
	}

	freeReplyObject(reply);
	reply = redisCommand(cachedb_ctx, "DEL %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	freeReplyObject(reply);

	destroy_cachedb();
}

/*
 * Helper function to extract each sub-string in cache string to 
 * struct answer form.
 */
static int str2answer(const char *string, struct answer *ans)
{
	struct answer out;
	const char *tmp;
	char *ptr, *tmp2;
	int count = 0, retval = 0;
	size_t len;

	tmp = string;
	while ((ptr = strchr(tmp, ','))) {
		tmp2 = xstrndup(tmp, ptr - tmp);

		/* qname */
		if (count == 0) {
			len = ptr - tmp;
			if (len >= sizeof(out.qname)) {
				free(tmp2);
				break;
			}
			memcpy(out.qname, tmp2, len);
			out.qname[len] = '\0';
		/* qtype */
		} else if (count == 1) {
			out.qtype = str2rr(tmp2);
		/* ttl */
		} else if (count == 2) {
			out.ttl = strtol(tmp2, NULL, 10);
		/* mx code */
		} else if (count == 3) {
			out.mx_code = strtol(tmp2, NULL, 10);
		}

		free(tmp2);

		if (count == 3)
			break;
		tmp = ++ptr;
		count++;
	}

	/* data */
	if (count == 3 && ptr != NULL) {
		tmp = ++ptr;
		len = strlen(tmp);
		if (len < sizeof(out.data)) {
			memcpy(out.data, tmp, len);
			out.data[len] = '\0';
			retval = 1;
		}
	}

	if (retval == 1)
		*ans = out;
	return retval;
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
	queue_t *out_res = NULL;
	queue_t *fil_res = NULL;
	queue_t *ptr_res;
	struct answer *ans, *tmp_ans;
	redisReply *reply;
	int value, i, retval = 0;
	int min_ttl = 0, cur_ttl, tmp_ttl;

	init_cachedb();

	reply = redisCommand(cachedb_ctx, "EXISTS %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	value = reply->integer;
	freeReplyObject(reply);

	/*
	 * If record was not found, search for possible NS/MX record's A query.
	 * PowerDNS always query for A record for NS/MX data.
	 * When error redirection and recursor is activated the key only used 
	 * to mark whether the name is exists or not.
	 */
	if (!value) {
		if (q->qtype_id == RR_TYPE_A) {
			value = lookup_a_record(q);
			if (value)
				retval = -2;
		}
		goto end;
	} else {
		if (config.redirect_error && config.use_recursor) {
			retval = -1;
			if (config.debug)
				fprintf(stderr, "<< %s: key exists >>\n", q->qname);
			goto end;
		}
	}

	/* Check if this record has been expired */
	reply = redisCommand(cachedb_ctx, "TTL %s:%s", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();
	cur_ttl = reply->integer;
	freeReplyObject(reply);
	if (cur_ttl < 0)
		goto end;

	reply = redisCommand(cachedb_ctx, "LRANGE %s:%s 0 -1", KEY_PREFIX, q->qname);
	if (!reply)
		cachedb_error();

	for (i = 0; i < reply->elements; i++) {
		ans = xmalloc(sizeof(struct answer));
		value = str2answer(reply->element[i]->str, ans);
		if (!value) {
			fprintf(stderr, "<< %s: error parsing cache data >>\n",q->qname);
			exit (EXIT_FAILURE);
		}
		out_res = queue_prepend(out_res, ans);
		if (i == 0)
			min_ttl = ans->ttl;
		else
			min_ttl = min_ttl < ans->ttl ? min_ttl : ans->ttl;
	}

	freeReplyObject(reply);
	if (i == 0) {
		fprintf(stderr, "<< %s: cache was expired while retrieving, "
			"min_ttl: %is >>\n", q->qname, min_ttl);
		goto end;
	}

	/* Set record's TTL, except for 0 TTL (hacked TTL on insert_cachedb) */
	ptr_res = out_res;
	while (ptr_res) {
		tmp_ans = ptr_res->data;
		if (min_ttl > 0) {
			tmp_ttl = tmp_ans->ttl - (min_ttl - cur_ttl);
			if (tmp_ttl < 0) {
				if (config.debug)
					fprintf(stderr, "<< %s: cache was expired, "
						"min_ttl: %is >>\n", q->qname, min_ttl);
				free_cachedb_data(out_res);
				goto end;
			}
			tmp_ans->ttl = tmp_ttl;
		}
		ptr_res = ptr_res->next;
	}

	/* Filter records output based on query type */
	if (q->qtype_id == RR_TYPE_ANY) {
		*res = out_res;
		retval = i;
	} else {
		retval = 0;
		ptr_res = out_res;
		while (ptr_res) {
			tmp_ans = ptr_res->data;
			if (tmp_ans->qtype == q->qtype_id) {
				ans = xmalloc(sizeof(struct answer));
				memcpy(ans, tmp_ans, sizeof(struct answer));
				fil_res = queue_prepend(fil_res, ans);
				retval++;
			}
			ptr_res = ptr_res->next;
		}

		free_cachedb_data(out_res);

		if (retval)
			*res = fil_res;
		else
			retval = -1;
	}

	if (config.debug && retval > 0) {
		if (q->qtype_id == RR_TYPE_ANY)
			fprintf(stderr, "<< %s: cache hits: %i records >>\n", 
				q->qname, retval);
		else
			fprintf(stderr, "<< %s: cache hits: %i/%i records >>\n", 
				q->qname, retval, i);
	}

end:
	destroy_cachedb();
	return retval;
}

int insert_log(const struct log *log)
{
	struct tm *st;
	static char cmd[BUFSIZ], reqtime[20];
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
	snprintf(reqtime, sizeof(reqtime), "%i-%.2i-%.2i %.2i:%.2i:%.2i", 
		st->tm_year + 1900, st->tm_mon + 1, st->tm_mday,
		st->tm_hour, st->tm_min, st->tm_sec);

	sprintf(cmd, "INSERT INTO %i_%.2i VALUES(NULL, '%s', '%s', "
		"'%s', '%s', %i, %i, %i, %i, %i)", st->tm_year + 1900,
		st->tm_mon + 1, reqtime, log->remote, log->qname, 
		type_str(log->qtype), log->qtime, log->ftime,
		log->blacklist, log->exist, log->status);

	ret = mysql_query(conn, cmd);

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
	snprintf(tmp, sizeof(tmp), "%s/cpdns_%s.log", config.log_dir, date);

	fp = fopen(tmp, "a");
	if (fp == NULL) {
		if (config.debug)
			fprintf(stderr, "<< could not open log file >>\n");
		return 0;
	}

	sprintf(time_string, "%s_%.2i:%.2i:%.2i", date, 
		st->tm_hour, st->tm_min, st->tm_sec);
	snprintf(tmp, sizeof(tmp), "%s\t%s\t%i\t%i\t%i\t%i\t%i\t%i\t%s\n", 
		time_string, log->remote, log->qtime, log->ftime, log->blacklist, 
		log->exist, log->status, backend_id, log->qname);

	ret = fprintf(fp, tmp);
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
	init_tldnode();

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

		/* 
		 * Sometime PowerDNS ask with asterisk '*' sign, eg '*.com' 
		 * don't have any idea yet so just discard it.
		 */
		if (*q.qname == '*') goto end;

		switch (do_query(&q)) {
			case LDNS_RCODE_SERVFAIL:
				puts("FAIL");
				if (config.debug)
					fprintf(stderr, "FAIL\n");
				break;

			default:
end:
				puts("END");
				if (config.debug)
					fprintf(stderr, "END\n");
		}
	}

	free_tldnode();

	return 0;
}
