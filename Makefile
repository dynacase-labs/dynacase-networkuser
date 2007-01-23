# ============================================
# $Id: Makefile,v 1.1 2007/01/23 10:45:35 eric Exp $
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

export targetdir PACKAGE

SUBDIR= Actions Javascript Images

include $(utildir)/PubRule

DISTFILES += $(SUBDIR) \
            RELEASE VERSION 


