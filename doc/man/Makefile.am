man1_MANS = \
	glite-ssss-split-key.1 \
	glite-ssss-join-key.1

EXTRA_DIST = $(addsuffix .xml,$(man_MANS))
CLEANFILES = $(man1_MANS) $(addsuffix .html,$(man1_MANS))

MAN_STYLESHEET = http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl
HTML_STYLESHEET = $(top_srcdir)/doc/man/html-output.xsl
LATEX_STYLESHEET = $(top_srcdir)/doc/man/latex-output.xsl

html_DATA = $(addsuffix .html,$(man1_MANS))

# this target is not required in the normal builds
# so one has to run it by hand to generate LaTeX
# formatted manual pages (you need the db2latex-xsl
# extension package for DocBook to use it!)
#
#       make texdoc
#
texdoc: $(addsuffix .tex,$(man1_MANS))

$(man1_MANS): %.1: %.1.xml $(COMMON_XMLFILES)
	$(XSLTPROC) $(XSLTPROCFLAGS) $(MAN_STYLESHEET) $<

$(addsuffix .html,$(man1_MANS)): %.1.html: %.1.xml $(HTML_STYLESHEET)
	$(XSLTPROC) $(XSLTPROCFLAGS) -o $@ $(HTML_STYLESHEET) $<

$(addsuffix .tex,$(man1_MANS)): %.1.tex: %.1.xml $(LATEX_STYLESHEET)
	$(XSLTPROC) $(XSLTPROCFLAGS) -o $@ $(LATEX_STYLESHEET) $<

