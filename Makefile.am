#
#  Copyright (c) Members of the EGEE Collaboration. 2005.
#  See http://eu-egee.org/partners/ for details on the copyright holders.
#  For license conditions see the license file or http://eu-egee.org/license.html
#
#  Main Makefile.am file for the gLite security ssss component
#
#  Authors: Akos Frohner <Akos.Frohner@cern.ch>
#  Version info: $Id: Makefile.am,v 1.1.1.1 2006-08-04 14:56:01 szamsu Exp $
#  Release: $Name: not supported by cvs2svn $

# Location of the macro files
ACLOCAL_AMFLAGS = -I project

SUBDIRS	= src interface doc

docdir = $(datadir)/doc/$(PACKAGE)
dist_doc_DATA = RELEASE-NOTES LICENSE

stage: install

distsrc: dist
	mv $(distdir).tar.gz $(DISTTAR)/$(distdir)_src.tar.gz

distbin: all
	mkdir -p $(top_builddir)/dist_bin/$(prefix)
	$(MAKE) $(AM_MAKEFLAGS) install DESTDIR=`cd $(top_builddir); pwd`/dist_bin
	(cd $(top_builddir)/dist_bin/$(prefix); $(AMTAR) -zcf $(DISTTAR)/$(distdir)_bin.tar.gz .)
	rm  -rf $(top_builddir)/dist_bin

.PHONY: stage distsrc distbin

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES = Makefile.in
