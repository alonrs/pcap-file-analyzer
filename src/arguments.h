#ifndef ARGUMENTS_H
#define ARGUMENTS_H

/* Returns argument "NAME" from "ARGS" with default value "DEF" */
#define ARG_INTEGER(ARGS, NAME, DEF)                   \
    (arg_find(ARGS, NAME) == NULL ?                    \
     DEF : atol(arg_find(ARGS, NAME)->value))
#define ARG_DOUBLE(ARGS, NAME, DEF)                    \
    (arg_find(ARGS, NAME) == NULL ?                    \
     DEF : atof(arg_find(ARGS, NAME)->value))
#define ARG_BOOL(ARGS, NAME, DEF)                      \
    (arg_find(ARGS, NAME) == NULL ?                    \
     DEF : arg_find(ARGS, NAME)->available)
#define ARG_STRING(ARGS, NAME, DEF)                    \
    (arg_find(ARGS, NAME) == NULL ?                    \
     DEF : arg_find(ARGS, NAME)->value)

/* Used to define and acquire command line arguments */
struct arguments {
    /* Set by the user */
    const char* name;
    int required;
    int is_boolean;
    const char* value;
    const char* help;

    /* Private */
    int available;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Prototypes */
void arg_parse(int argc, char **argv, struct arguments*);
struct arguments* arg_find(struct arguments*, const char*);

#ifdef __cplusplus
}
#endif

#endif
