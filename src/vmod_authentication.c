#include <stdlib.h>
#include <stdio.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#include "base64.h"

typedef struct{
	char *username;
	char *password;
} combination;

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return 0;
}

combination *
parse_auth_header(const char *data, size_t len)
{
	combination *c = malloc(sizeof(combination));
	
	char *split = strchr(data, ':');
	if(split == NULL) {
		// not in user:pass format
		return NULL;
	}
	
	c->username = strndup(data, split - data);
	c->password = strndup(split + 1, len - (split - data) - 1);
	
	return c;
}

combination *
get_client_auth(struct sess *sp)
{
	char *auth_hdr = VRT_GetHdr(sp, HDR_REQ, "\016Authorization:");
	if(auth_hdr == NULL) {
		return NULL;
	}
	
	char *split = strchr(auth_hdr, ' ');
	if(split == NULL) {
		// invalid header data
		return NULL;
	}
	
	// assuming Basic, for now (TODO: don't assume)
	char *auth = strdup(split + 1);
	
	size_t len;
	char *decoded;
	
	if(!base64_decode_alloc(auth, strlen(auth), &decoded, &len)) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to allocate space for decoding base64");
		
		free(auth);
		return NULL;
	}
	
	if(!base64_decode(auth, strlen(auth), decoded, &len)) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to make sense of base64 encoded credentials");
		
		free(decoded);
		free(auth);
		return NULL;
	}
	
	combination *c = parse_auth_header(decoded, len);
	
	if(c == NULL) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to make sense of authorization header");
		
		free(decoded);
		free(auth);
		return NULL;
	}
	
	free(auth);
	free(decoded);
	
	return c;
}

unsigned
vmod_match(struct sess *sp, const char *username, const char *password)
{
	combination *c = get_client_auth(sp);
	if(c == NULL) {
		// invalid header
		return false;
	}
	
	if(strcmp(c->username, username) != 0 || strcmp(c->password, password) != 0) {
		free(c->username);
		free(c->password);
		free(c);
		return false;
	}
	
	free(c->username);
	free(c->password);
	free(c);
	
	return true;
}


