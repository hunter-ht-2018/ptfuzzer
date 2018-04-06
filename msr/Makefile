## -----------------------------------------------------------------------
##   
##   Copyright 2000 Transmeta Corporation - All Rights Reserved
##
##   This program is free software; you can redistribute it and/or modify
##   it under the terms of the GNU General Public License as published by
##   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
##   USA; either version 2 of the License, or (at your option) any later
##   version; incorporated herein by reference.
##
## -----------------------------------------------------------------------

#
# Makefile for MSRs
#

CC       = gcc -Wall
CFLAGS   = -g -O2 -fomit-frame-pointer -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS  = 

BIN	= wrmsr rdmsr cpuid

sbindir = /usr/sbin

all: $(BIN)

clean:
	rm -f *.o $(BIN)

distclean: clean
	rm -f *~ \#*

install: all
	install -m 755 $(BIN) $(sbindir)

.o:
	$(CC) $(LDFLAGS) -o $@ $<

.c.o:
	$(CC) $(CFLAGS) -o $@ $<

.c:
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
