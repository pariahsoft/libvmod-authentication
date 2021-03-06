===================
vmod_authentication
===================

----------------------------------
Varnish HTTP Authentication Module
----------------------------------

:Author: Omega Software Development Group
:Date: 2011-11-24
:Version: 0.9
:Manual section: 3

SYNOPSIS
========

import authentication;

DESCRIPTION
===========

Implements basic HTTP authentication in Varnish.

FUNCTIONS
=========

match
-----

Prototype
	match(STRING username, STRING password)
Return value
	BOOL
Description
	Tests the client's given credentials (if any) against a specified username and password, returning true if matched.
Example
	Throwing a "401 Authentication Required" error if the client fails to authenticate as **admin** with password **test**.
	::
		if(req.url ~ "^/protected/") {
			if(!authentication.match("admin", "test")) {
				error 401 "Authentication Required";
			}
		}

COPYRIGHT
=========

This document is licensed under the same license as the
libvmod-example project. See LICENSE for details.

* Copyright (c) 2011 Omega Software Development Group

