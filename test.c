/* 
 * Based on ldns's mx examples <http://www.nlnetlabs.nl/projects/ldns/>
 * High modified by Ardhan Madras <ajhwb@knac.com>
 */

#include <ldns/ldns.h>
#include <ldns/host2str.h>
#include <stdio.h>

static int
usage(FILE *fp, const char *prog) 
{
	fprintf(fp, "Usage: %s domain\n", prog);
	return 0;
}

static void
process_rdf (const ldns_rr *rr)
{
	ldns_rdf *rdf;
	ldns_buffer *output;
	ldns_status res = LDNS_STATUS_OK;
	char *str;
	int i;

	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
		rdf = ldns_rr_rdf(rr, i);
		output = ldns_buffer_new(LDNS_MAX_PACKETLEN);

		switch (ldns_rdf_get_type(rdf)) {
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
				printf("(%i)", ldns_rdf_get_type(rdf));
				break;
		}

		if (res != LDNS_STATUS_OK) {
			printf("(rdf error)");
			continue;
		}

		str = ldns_buffer2str(output);
		ldns_buffer_free(output);
		printf("%s", str);
		LDNS_FREE(str);
		if (i < ldns_rr_rd_count(rr) - 1)
			printf(" ");
	}
}

static void
process_type (const ldns_pkt *p, int type)
{
        ldns_rr_list *list;
	ldns_rr *rr;
	int32_t i, j;

        list = ldns_pkt_rr_list_by_type(p, type, LDNS_SECTION_ANSWER);
        if (list) {
        	ldns_rr_list_sort(list);
		for (i = 0; i < ldns_rr_list_rr_count(list); i++) {
			rr = ldns_rr_list_rr(list, i);
			printf("%s", ldns_rr_get_class(rr) == LDNS_RR_CLASS_IN ? "IN" : "(unknown)");

			printf("\t%i", ldns_rr_ttl(rr));

			type = ldns_rr_get_type(rr);
			if (type == LDNS_RR_TYPE_A) printf("\tA\t");
			else if (type == LDNS_RR_TYPE_AAAA) printf("\tAAAA\t");
			else if (type == LDNS_RR_TYPE_SOA) printf("\tSOA\t");
			else if (type == LDNS_RR_TYPE_NS) printf("\tNS\t");
			else if (type == LDNS_RR_TYPE_MX) printf("\tMX\t");
			else if (type == LDNS_RR_TYPE_TXT) printf("\tTXT\t");
			else if (type == LDNS_RR_TYPE_CNAME) printf("\tCNAME\t");
			else {
				printf("\t(unknown)\t...\n");
				continue;
			}
			process_rdf(rr);
			putchar('\n');
		}
        }
	ldns_rr_list_deep_free(list);
}

int
main(int argc, char *argv[])
{
         ldns_resolver *res;
         ldns_rdf *domain;
         ldns_pkt *p;
         ldns_rr_list *mx;
         ldns_status s;

         p = NULL;
         mx = NULL;
         domain = NULL;
         res = NULL;

         if (argc != 2) {
                 usage(stdout, argv[0]);
                 exit(EXIT_FAILURE);
         } else {
                 /* create a rdf from the command line arg */
                 domain = ldns_dname_new_frm_str(argv[1]);
                 if (!domain) {
                         usage(stdout, argv[0]);
                         exit(EXIT_FAILURE);
                 }
         }

         /* create a new resolver from /etc/resolv.conf */
         s = ldns_resolver_new_frm_file(&res, NULL);
 
         if (s != LDNS_STATUS_OK) {
                 exit(EXIT_FAILURE);
         }
 
         /* use the resolver to send a query for the mx 
          * records of the domain given on the command line
          */
	p = ldns_resolver_query(res,
				domain,
				LDNS_RR_TYPE_ANY,
				LDNS_RR_CLASS_IN,
				LDNS_RD);
 
	ldns_rdf_deep_free(domain);
	if (!p) {
		fprintf(stderr, "p is NULL\n");
		exit(EXIT_FAILURE);
	}

	process_type(p, LDNS_RR_TYPE_A);
	process_type(p, LDNS_RR_TYPE_SOA);
	process_type(p, LDNS_RR_TYPE_NS);
	process_type(p, LDNS_RR_TYPE_AAAA);
	process_type(p, LDNS_RR_TYPE_MX);
	process_type(p, LDNS_RR_TYPE_TXT);
	process_type(p, LDNS_RR_TYPE_CNAME);

	ldns_pkt_free(p);
	ldns_resolver_deep_free(res);
	return 0;
}

