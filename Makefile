# ============================================
# $Id: Makefile,v 1.3 2007/01/31 17:48:24 eric Exp $
# ============================================
PACKAGE = FREEDOM-AD
VERSION = 0.0.0
utildir=/home/eric/anakeen/what
appname = AD
pubdir = /usr/share/what
srcdir = .

export pubdir utildir appname

TAR = gtar
GZIP_ENV = --best
TOP_MODULES = ad.php
export targetdir PACKAGE

SUBDIR= Class Api Images

include $(utildir)/PubRule

DISTFILES += $(SUBDIR) \
            RELEASE VERSION 


