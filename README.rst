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
		if(!authentication.match("admin", "test")) {
			error 401 "Authentication Required";
		}

match_file
-----

Prototype
	match_file(STRING filename)
Return value
	BOOL
Description
	Tests the client's given credentials (if any) against a set of accepted username and password combinations, listed line-by-line in **filename**.
Example
	Throwing a "401 Authentication Required" error if the client fails to authenticate with any of the following combinations:
	::
		user1:password1
		user2:password2
		user3:password3
	
	::
		if(!authentication.match_file("passwords.pwd")) {
			error 401 "Authentication Required";
		}

COPYRIGHT
=========

This document is licensed under the same license as the
libvmod-example project. See LICENSE for details.

* Copyright (c) 2011 Omega Software Development Group

