#include <stdlib.h>
#include <stdio.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#include "base64.h"

#define BASE64_MAX_LEN		100

typedef struct {
	size_t username_len;
	size_t password_len;
	char *username;
	char *password;
} combination;

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

combination
parse_authorization(const char *encoded)
{
	size_t decoded_len = BASE64_MAX_LEN;
	char *decoded = malloc(decoded_len);
	
	// base64 decode
	if(!base64_decode(encoded, strlen(encoded), decoded, &decoded_len)) {
		// input data was invalid
	}
	
	combination c;
	c.username_len = 0;
	c.password_len = 0;
	c.username = NULL;
	c.password = NULL;
	
	int part = 0; // 0 = username; 1 = password
		
	for(unsigned int i = 0; i < decoded_len; i++) {
		if(part == 0) {
			if(decoded[i] == ':') {
				part = 1;
			} else {
				c.username = realloc(c.username, (c.username_len++)+1);
				c.username[c.username_len - 1] = decoded[i];
				c.username[c.username_len] = 0;
			}
		} else {
			c.password = realloc(c.password, (c.password_len++)+1);
			c.password[c.password_len - 1] = decoded[i];
			c.password[c.password_len] = 0;
		}
	}
	
	free(decoded);
	
	return c;
}

unsigned
vmod_match(struct sess *sp, const char *username, const char *password, const char *encoded)
{
	combination c = parse_authorization(encoded);
	
	bool result = strcmp(c.username, username) == 0 &&strcmp(c.password, password) == 0;
	
	free(c.username);
	free(c.password);
	
	return result;
}



