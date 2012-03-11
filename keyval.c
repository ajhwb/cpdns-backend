/**
 * Keyvalue File Parser
 *
 * Copyright(C) 2012 - Ardhan Madras <ajhwb@knac.com>
 *
 * This software is free software, you can use, modify and distribute
 * under the term of GPL v2 license.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMENT_CHAR	'#'
#define EQUAL_CHAR	'='
#define SPACE_CHAR	' '
#define NULL_CHAR	'\0'
#define LF_CHAR		'\n'
#define CR_CHAR		'\r'
#define FALSE_STR	"false"
#define TRUE_STR	"true"

struct _keyval_t {
	char *buffer;
	const char *false_str;
	const char *true_str;
};

typedef struct _keyval_t keyval_t;

static void strstrip(char *str)
{
        char *ptr;
        int i;

        /* Remove any space after non space character */
	do {
		ptr = str;
		while (*ptr != NULL_CHAR)
			ptr++;
		if (ptr == str)
			break;
		if (*--ptr == SPACE_CHAR)
			*ptr = NULL_CHAR;
	} while (*ptr == NULL_CHAR);

	/* Remove any space before non space character */
	while (*str == SPACE_CHAR) {
		i = 0;
		do {
			str[i] =  str[i + 1];
		} while (str[i++] != NULL_CHAR);
	}
}

#define next_line(tmp) \
do { \
	while (*tmp) { \
		if (*tmp == LF_CHAR) \
			break; \
		if (*tmp++ == CR_CHAR && *tmp == LF_CHAR) \
			break; \
	} \
	if (*tmp) \
		tmp++; \
} while (0);

inline static char *get_line(char *tmp)
{
	char *ptr = tmp;
	int len = 0;

	while (*ptr != LF_CHAR) {
		if (*ptr++ == CR_CHAR && *ptr == LF_CHAR)
			break;
		len++;
	}

	if (len == 0)
		return NULL;

	ptr = (char*) malloc(len + 1);
	if (ptr) {
		memcpy(ptr, tmp, len);
		*(ptr + len) = NULL_CHAR;
	}
	return ptr;
}

inline static char *get_value(char *line, const char *key)
{
	char *ptr, *tmp;
	int len, i;

	ptr = strchr(line, EQUAL_CHAR);
	if (!ptr)
		return NULL;

	len = ptr - line;
	tmp = (char*) malloc(len + 1);
	if (!tmp)
		return NULL;
	memcpy(tmp, line, len);
	*(tmp + len) = NULL_CHAR;

	/*
	 * Strip if the key has some space char, start from latest character 
	 * before '\0', so it can handle key such as ' my key  = value  '.
	 */
	strstrip(tmp);
	i = strcmp(tmp, key);
	free(tmp);
	if (i != 0)
		return NULL;

	ptr++;
	if (*ptr == NULL_CHAR) {
		tmp = (char*) malloc(1);
		if (!tmp)
			return NULL;
		*tmp = *ptr;
	} else {
		len = strlen(ptr);
		tmp = (char*) malloc(len + 1);
		if (!tmp)
			return NULL;
		memcpy(tmp, ptr, len);
		*(tmp + len) = NULL_CHAR;
		strstrip(tmp);
	}

	return tmp;
}

inline static int is_comment(const char *line)
{
	const char *ptr = line;
	int retval = 0;

	while (*ptr == SPACE_CHAR)
		ptr++;
	if (*ptr == COMMENT_CHAR)
		return !retval;
	return retval;
}

keyval_t *keyval_new(const char *filename)
{
	keyval_t *keyval;
	FILE *fp;
	char *buffer;
	long size;
	int ret, i = 0;

	fp = fopen(filename, "r");
	if (!fp)
		return NULL;

	ret = fseek(fp, 0L, SEEK_END);
	if (ret < 0)
		return NULL;

	size = ftell(fp);
	buffer = (char*) malloc(size + 1);
	if (!buffer) {
		fclose(fp);
		return NULL;
	}

	rewind(fp);
	while ((ret = getc(fp)) != EOF) {
		buffer[i] = ret;
		i++;
	}
	buffer[i] = NULL_CHAR;
	(void) fclose(fp);

	keyval = (keyval_t*) malloc(sizeof(keyval_t));
	if (!keyval) {
		free(buffer);
		return NULL;
	}

	keyval->buffer = buffer;
	keyval->false_str = FALSE_STR;
	keyval->true_str = TRUE_STR;
	return keyval;
}

void keyval_free(keyval_t *keyval)
{
	if (keyval)
		free(keyval->buffer);
}

void keyval_set_true_str(keyval_t *keyval, const char *str)
{
	keyval->true_str = str;
}

void keyval_set_false_str(keyval_t *keyval, const char *str)
{
	keyval->false_str = str;
}

char *keyval_get_string(keyval_t *keyval, const char *key)
{
	char *buffer = keyval->buffer;
	char *retval = NULL;
	char *line;

	while (*buffer) {
		line = get_line(buffer);
		if (line) {
			if (!is_comment(line))
				retval = get_value(line, key);
			free(line);
			if (retval)
				break;
		}
		next_line(buffer);
	}
	return retval;
}

int keyval_get_integer(keyval_t *keyval, const char *key)
{
	char *value;
	int retval = 0;

	value = keyval_get_string(keyval, key);
	if (value) {
		retval = strtol(value, NULL, 10);
		free(value);
	}
	return retval;
}

int keyval_get_boolean(keyval_t *keyval, const char *key)
{
	char *value;
	int retval = 0;

	value = keyval_get_string(keyval, key);
	if (value) {
		retval = strcmp(keyval->false_str, value);
		if (!retval) {
			free(value);
			return retval;
		}

		retval = strcmp(keyval->true_str, value);
		free(value);
		if (!retval)
			return !retval;
	}
	return 0;
}
