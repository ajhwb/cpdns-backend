#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int extract_domain(char *url, char ***result)
{
	int ret = 0;
	char **data = NULL, *tmp, *ptr;

	if (url == NULL)
		return ret;

	data = realloc(data, sizeof(char*));
	if (data == NULL)
		return -1;
	data[ret] = strdup(url);

	ptr = url;
	while ((tmp = strchr(ptr, '.'))) {
		ret++;
		data = realloc(data, sizeof(char*) * (ret + 1));
		if (data == NULL)
			return -1;
		ptr = ++tmp;
		data[ret] = strdup(ptr);
	}

	if (*ptr) {
		ret++;
		data = realloc(data, sizeof(char*) * (ret + 1));
		data[ret] = strdup(ptr);
	}

	*result = data;
	return ret;
}

int main(int argc, char *argv[])
{
	char *progname, *tmp;
	char **domains;
	int ret;

	if ((tmp = strrchr(argv[0], '/')))
		progname = ++tmp;

	if (argc < 2) {
		fprintf(stderr, "usage: %s domain\n", progname);
		return 1;
	}

	ret = extract_domain(argv[1], &domains);
	if (ret > 0) {
		while (ret--) {
			puts(domains[ret]);
			free(domains[ret]);
		}
		free(domains);
	}

	return 0;
}
