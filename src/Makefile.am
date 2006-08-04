#
#  Copyright (c) Members of the EGEE Collaboration. 2005.
#  See http://eu-egee.org/partners/ for details on the copyright holders.
#  For license conditions see the license file or http://eu-egee.org/license.html
#
# Authors: Akos Frohner <Akos.Frohner@cern.ch>
# Version info: $Id: Makefile.am,v 1.2 2006-08-04 15:22:05 szamsu Exp $
# Release: $Name: not supported by cvs2svn $


CPPFLAGS += -I$(top_srcdir)/interface $(GLITE_CFLAGS)
LDFLAGS += -L$(GLITE_LOCATION)/lib 

MAINTAINERCLEAN = Makefile.in

AM_CPPFLAGS = $(GLOBUS_THR_CFLAGS) 

lib_LTLIBRARIES = libglite_security_ssss.la 

libglite_security_ssss_la_SOURCES = shamir.c shamir-funcs.c

libglite_security_ssss_la_LIBADD = \
	-L$(GLITE_LOCATION)/lib -lm -lcrypto
	
libglite_security_ssss_la_LDFLAGS = \
	-version-info $(INTERFACE_LIBTOOL_CURRENT):$(INTERFACE_LIBTOOL_REVISION):$(INTERFACE_LIBTOOL_AGE)

bin_PROGRAMS = \
	glite-ssss-split-key \
	glite-ssss-join-key

noinst_PROGRAMS = \
	test-shamir

glite_ssss_split_key_SOURCES = splitKey.c
glite_ssss_split_key_LDADD = libglite_security_ssss.la

glite_ssss_join_key_SOURCES = joinKey.c
glite_ssss_join_key_LDADD = libglite_security_ssss.la

test_shamir_SOURCES = test-shamir.c
test_shamir_LDADD = libglite_security_ssss.la

