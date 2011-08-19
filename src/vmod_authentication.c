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
parse_auth_header(const char *data)
{
	combination *c = malloc(sizeof(combination));
	
	char *split = strchr(data, ':');
	if(split == NULL) {
		// not in user:pass format
		return NULL;
	}
	c->username = strndup(data, split - data);
	c->password = strdup(split + 1);
	
	return c;
}

combination *
get_client_auth(struct sess *sp)
{
	char *auth_hdr = VRT_GetHdr(sp, HDR_REQ, "\16Authorization:");
	if(auth_hdr == NULL)
		return NULL;
	
	char *split = strchr(auth_hdr, ' ');
	if(split == NULL) {
		// invalid header data
		return false;
	}
	
	// assuming Basic, for now (TODO: don't assume)
	char *auth = strdup(split + 1);
	
	size_t decoded_len = BASE64_MAX_LEN;
	char *decoded = malloc(decoded_len);
	
	// base64 decode
	if(!base64_decode(auth, strlen(auth), decoded, &decoded_len)) {
		// input data was invalid
		return NULL;
	}
	
	combination *c = parse_auth_header(decoded);
	if(c == NULL) {
		// something was invalid
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
	if(c == NULL)
		return false;
	
	bool result = strcmp(c->username, username) == 0 && strcmp(c->password, password) == 0;
	
	free(c->username);
	free(c->password);
	free(c);
	
	return result;
}

unsigned
vmod_match_file(struct sess *sp, const char *filename)
{
	combination *c = get_client_auth(sp);
	if(c == NULL)
		return false;
	
	
	bool result = false;
	char line[100];
	combination *match;
	
	FILE* fp = fopen(filename, "r");
	if(fp == NULL) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to open file %s", filename);
		return false;
	}
	
	while(!result && fgets(line, sizeof(line), fp)) {
		if(line[strlen(line) - 1] == '\n')
			line[strlen(line)-1] = 0;
		
		match = parse_auth_header(line);
		if(match == NULL)
			continue;
		
		if(strcmp(c->username, match->username) == 0 && strcmp(c->password, match->password) == 0) {
			result = true;
		}
		
		free(match->username);
		free(match->password);
		free(match);
	}
	fclose(fp);
	
	free(c->username);
	free(c->password);
	free(c);
	
	return result;
}


