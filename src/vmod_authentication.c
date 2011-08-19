#include <stdlib.h>
#include <stdio.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#include "base64.h"

#define BASE64_MAX_LEN		100

typedef struct {
	char *username;
	char *password;
} combination;

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

combination *
parse_authorization(const char *encoded)
{
	size_t decoded_len = BASE64_MAX_LEN;
	char *decoded = malloc(decoded_len);
	
	// base64 decode
	if(!base64_decode(encoded, strlen(encoded), decoded, &decoded_len)) {
		// input data was invalid
		return NULL;
	}
	
	combination *c = malloc(sizeof(combination));
	
	char *split = strchr(decoded, ':');
	if(split == NULL) {
		// not in user:pass format
		return NULL;
	}
	c->username = strndup(decoded, split - decoded);
	c->password = strdup(split + 1);
	
	free(decoded);
	free(split);
	
	return c;
}

unsigned
vmod_match(struct sess *sp, const char *username, const char *password, const char *encoded)
{
	combination *c = parse_authorization(encoded);
	
	if(c == NULL) {
		// something was invalid
		return false;
	}
	
	printf("Test: %s\n", c->username);
	
	bool result = strcmp(c->username, username) == 0 && strcmp(c->password, password) == 0;
	
	free(c->username);
	free(c->password);
	free(c);
	
	return result;
}



