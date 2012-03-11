#ifndef _KEYVAL_H
#define _KEYVAL_H

struct _keyval_t;

typedef struct _keyval_t keyval_t;

#ifdef __cplusplus
extern "C" {
#endif

keyval_t *keyval_new(const char *filename);
void keyval_free(keyval_t *keyval);
void keyval_set_true_str(keyval_t *keyval, const char *str);
void keyval_set_false_str(keyval_t *keyval, const char *str);
char *keyval_get_string(keyval_t *keyval, const char *key);
int keyval_get_integer(keyval_t *keyval, const char *key);
int keyval_get_boolean(keyval_t *keyval, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* _KEYVAL_H */
