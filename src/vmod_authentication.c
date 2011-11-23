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

char *_getline(FILE *fp)
{
	char * line = malloc(20), * linep = line;
	size_t lenmax = 20, len = lenmax;
	int c;

	if(line == NULL)
		return NULL;

	while(1) {
		c = fgetc(fp);
		if(c == EOF)
			return NULL;
		
		if(c == '\n')
			break;
		
		if(--len == 0) {
			char * linen = realloc(linep, lenmax *= 2);
			len = lenmax;

			if(linen == NULL) {
				free(linep);
				return NULL;
			}
			line = linen + (line - linep);
			linep = linen;
		}
		
		*line++ = c;
	}
	
	*line = '\0';
	return linep;
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return 0;
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
	
	size_t len;
	char *decoded;
	
	if(!base64_decode_alloc(auth, strlen(auth), &decoded, &len)) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to allocate space for decoding base64");
		
		free(auth);
		return NULL;
	}
	
	if(!base64_decode(auth, strlen(auth), decoded, &len)) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to make sense of base64 encoded credentials");
		
		free(auth);
		return NULL;
	}
	
	
	combination *c = parse_auth_header(decoded);
	
	if(c == NULL) {
		// something was invalid
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
	if(c == NULL)
		return false;
	bool result = strcmp(c->username, username) == 0 && strcmp(c->password, password) == 0;
	
	free(c->username);
	free(c->password);
	
	return result;
}

unsigned
vmod_match_file(struct sess *sp, const char *filename)
{
	combination *c = get_client_auth(sp);
	if(c == NULL)
		return false;
	
	bool result = false;
	combination *match;
	
	FILE* fp = fopen(filename, "r");
	if(fp == NULL) {
		WSP(sp, SLT_VCL_Log, "vmod_authentication: unable to open file %s", filename);
	} else {
		char *line;
		
		while(!result && (line = _getline(fp)) != NULL) {
			// retrieve username and password for current line
			match = parse_auth_header(line);
			if(match == NULL) {
				free(line);
				continue;
			}
			
			// test the combinations against eachother
			if(strcmp(c->username, match->username) == 0 && strcmp(c->password, match->password) == 0) {
				result = true;
			}
			
			free(match->username);
			free(match->password);
			free(match);
		}
		fclose(fp);
	}
	
	free(c->username);
	free(c->password);
	
	return result;
}

