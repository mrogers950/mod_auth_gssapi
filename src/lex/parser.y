/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms
 *
 * Bison file for the GssapiRequiredNameAttributes option parser.
 *
 * Rule := (RequiredKV | "(" Rule ")"),  { ' ', (AND|OR), ' ', Rule } ;
 * RequiredKV := Key, "=", Value ;
 * Key := <string>
 * Value := <string> | '*' ;
 * AND := "and" | "AND" ;
 * OR := "or" | "OR" ;
 *
 */
%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int yylex(void);
typedef struct yy_buffer_state * YY_BUFFER_STATE;
extern void yyerror(const char **keys, const char **vals,
                    int *status, const char *s);
extern int yyparse(const char **keys, const char **vals, int *status);
extern YY_BUFFER_STATE yy_scan_string(char * str);
extern void yy_delete_buffer(YY_BUFFER_STATE buffer);
static int hex2bincmp(const char *hex, size_t hex_len,
                      unsigned char *bin, size_t bin_len);
%}

%union {
    char *sval;
    int ival;
}

%token LPAREN
%token RPAREN
%token SPACE
%token OR
%token AND
%token EQUAL
%token AST
%token STRING
%token INT

%type <sval> STRING
%type <ival> INT rule rule_start requiredkv

%parse-param {const char **keys} {const char **vals} {int *status}

%%

expr: rule {
      if (status != NULL)
          *status = $1;
    }
    ;

rule: rule_start
    | rule_start SPACE AND SPACE rule {
      $$ = $1 && $5;
    }
    | rule_start SPACE OR SPACE rule {
      $$ = $1 || $5;
    }
    ;

rule_start: LPAREN rule RPAREN {
            $$ = $2;
          }
          | requiredkv {
            $$ = $1;
          }
          ;

requiredkv: STRING EQUAL STRING {
            int ret = 0;
            if (keys != NULL && vals != NULL) {
                for (int i = 0; keys[i] != NULL && vals[i] != NULL; i++) {
                    if (strcmp($1, keys[i]) != 0) {
                        continue;
                    }
                    if (($3[0] == '[') && ($3[strlen($3) - 1] == ']')) {
                        if (hex2bincmp($3 + 1, strlen($3) - 2,
                                       (unsigned char *)vals[i],
                                       strlen(vals[i]))) {
                            ret = 1;
                            break;
                        } else {
                            continue;
                        }
                    }
                    if ((strlen($3) == strlen(vals[i])) &&
                        (strcmp($3, vals[i]) == 0)) {
                        ret = 1;
                        break;
                    }
                }
            }
            $$ = ret;
          }
          | STRING EQUAL AST {
            int ret = 0;
            if (keys != NULL && vals != NULL) {
                for (int i = 0; keys[i] != NULL && vals[i] != NULL; i++) {
                    if (strcmp($1, keys[i]) == 0) {
                       ret = 1;
                       break;
                    }
                }
            }
            $$ = ret;
          }
          ;

%%

static int hexchar(unsigned int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

/* Convert hex_len of hex characters into binary and memcmp against bin. Return
 * 1 if the hex string is valid and matches, else 0. */
static int hex2bincmp(const char *hex, size_t hex_len,
                      unsigned char *bin, size_t bin_len)
{
    int r;
    unsigned char *b;
    size_t b_len, i;

    for (i = 0; i < hex_len && hex[i] != '\0'; i++) {
        if (hexchar(hex[i]) == -1)
            return 0;
    }

    b_len = i;
    if ((b_len & 1) != 0)
        return 0;

    b_len /= 2;

    if (b_len != bin_len)
        return 0;

    b = calloc(b_len, sizeof(*b));
    if (b == NULL)
        return 0;

    for (i = 0; i < b_len; i++)
        b[i] = hexchar(hex[i * 2]) << 4 | hexchar(hex[i * 2 + 1]);

    r = memcmp(b, bin, b_len);
    free(b);

    return r == 0;
}

/* Return 1 if the given name attributes and values (NULL terminated arrays)
 * satisfy the expression.  This does not handle parsing errors from yyparse,
 * so expr should be checked by required_name_attr_expr_check() first. */
int mag_verify_name_attributes(const char *expr, const char **attrs,
                               const char **vals)
{
    int ret = 0, status = 0;
    YY_BUFFER_STATE buffer;

    /* No name attribute requirements. Pass. */
    if (expr == NULL) {
        return 1;
    }

    /* No name attributes but required attributes are specified. Fail. */
    if (attrs == NULL || vals == NULL ||
        attrs[0] == NULL || vals[0] == NULL) {
        return 0;
    }

    buffer = yy_scan_string((char *)expr);
    ret = yyparse(attrs, vals, &status);
    yy_delete_buffer(buffer);

    return ret == 0 && status;
}

/* Return 1 if the expression is provided and valid, else return 0. */
int mag_check_name_attr_expr(const char *expr)
{
    int ret;
    YY_BUFFER_STATE buffer = yy_scan_string((char *)expr);

    /* Just verify the syntax. */
    ret = yyparse(NULL, NULL, NULL);
    yy_delete_buffer(buffer);

    return ret == 0;
}

/* Define a no-op yyerror().  Syntax errors are logged outside of calling
 * required_name_attr_expr_check(). */
void yyerror(const char **keys, const char **vals, int *status, const char *s)
{
    return;
}
