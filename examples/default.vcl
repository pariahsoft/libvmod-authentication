# This is a basic VCL configuration file for varnish.  See the vcl(7)
# man page for details on VCL syntax and semantics.
# 
# Default backend definition.  Set this to point to your content
# server.
# 
backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

import authentication;

sub vcl_recv {
	if(!authentication.match("admin", "test")) {
		error 401 "Authentication Required";
	}
	
	return (lookup);
}

sub vcl_error {
	if(obj.status == 401) {
		set obj.http.WWW-Authenticate = "Basic realm=Secure Area";
	}
}

