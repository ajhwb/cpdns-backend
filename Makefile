# Custom PowerDNS Backend
# Copyright (C) 2011 - Ardhan Madras <ajhwb@knac.com>

SOURCES       = queue.c backend.c
OBJS          = $(SOURCES:.c=.o)
CFLAGS        = -W -Wall -Wno-sign-compare -O3 -I${PWD}
GLIBCFLAGS    = `pkg-config --cflags glib-2.0`
GLIBLDFLAGS   = `pkg-config --libs glib-2.0`
MYSQLLDFLAGS  = -L/usr/lib/mysql -L/usr/lib64/mysql -lmysqlclient -lpq
LIBS          = -L/usr/local/lib -lrt -lsqlite3 -lldns -lhiredis
CC            = gcc
TARGET        = backend
DEST          = /etc/pdns/

${TARGET}: ${OBJS}
	@echo ' [LD]  ${OBJS} ${TARGET}'
	@${CC} ${GLIBLDFLAGS} ${MYSQLLDFLAGS} ${LIBS} \
		-o ${TARGET} ${OBJS}

.c.o:
	@echo ' [CC]  $<'
	@${CC} ${CFLAGS} ${GLIBCFLAGS} -c $<

.PHONNY:
install: ${TARGET}
	@cp ${TARGET} ${DEST}

.PHONNY:
test: test.o
	@echo ' [LD]  test.o'
	@${CC} ${LIBS} test.o -o test

clean:
	rm -rf *.o ${TARGET} test
