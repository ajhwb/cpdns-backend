# Custom PowerDNS Backend
# Copyright (C) 2011 - Ardhan Madras <ajhwb@knac.com>

SOURCES       = queue.c keyval.c regdom.c backend.c
OBJS          = $(SOURCES:.c=.o)
CFLAGS        = -W -Wall -Wno-sign-compare -O3 -g -I${PWD} -D_KDNS
MYSQLLDFLAGS  = `mysql_config --libs`
LIBS          = -L/usr/local/lib -lrt -lpthread -lldns -lhiredis
CC            = gcc
TARGET        = backend
DEST          = /etc/pdns/

${TARGET}: ${OBJS}
	@echo ' [LD]  ${TARGET}'
	@${CC} ${LIBS} ${MYSQLLDFLAGS} \
		-o ${TARGET} ${OBJS}

.c.o:
	@echo ' [CC]  $<'
	@${CC} ${CFLAGS} -c $<

.PHONNY:
install: ${TARGET}
	@cp ${TARGET} ${DEST}

.PHONNY:
test: test.o
	@echo ' [LD]  test.o'
	@${CC} ${LIBS} test.o -o test

clean:
	rm -rf *.o ${TARGET} test
