.include <bsd.own.mk>

PROG=	netsniffer
MAN=	netsniffer.1
SRCS=	netsniffer.c

.if defined(DEBUG)
CFLAGS +=	-DDEBUG=1 
CFLAGS +=	-dgdb
.endif

CFLAGS +=	-lpthread

.include <bsd.prog.mk>
