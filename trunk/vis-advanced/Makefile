#
# Copyright (C) 2006 BATMAN contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

CC = gcc
CFLAGS =         -Wall -W -O0 -g3 -DDEBUG_MALLOC -DMEMORY_USAGE
LDFLAGS =        -lpthread
LDFLAGS_STATIC = -lpthread -static


SRC_C= allocate.c hash.c list-batman.c vis.c udp_server.c
SRC_H= allocate.h hash.h list-batman.h vis.h vis-types.h
SRC_O=		$(SRC_C:.c=.o)


vis-adv:	$(SRC_O) Makefile
		$(Q_LD)$(CC) $(CFLAGS) -o $@ $(SRC_O) $(LDFLAGS)

vis-adv-static:	$(SRC_O) Makefile
		$(Q_LD)$(CC) $(CFLAGS) -o $@ $(SRC_O) $(LDFLAGS_STATIC)

%.o: %.c %.h
	$(Q_CC)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

%.o: %.c
	$(Q_CC)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

clean:
		rm -f vis-adv vis-adv-static *.o *~
