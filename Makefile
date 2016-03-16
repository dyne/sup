CC?=gcc
LDD?=ld
DESTDIR?=
PREFIX?=/usr/local
VERSION=0.2
USER=root
GROUP=root

CFLAGS?=-Os -O2

musl: musl=/usr/local/musl
musl: CC=/usr/local/musl/bin/musl-gcc
musl: CFLAGS+=-I${musl}/include
musl: LDFLAGS+=-static ${musl}/lib/libc.a
musl: config.h sup.o sha256.o
	${CC} ${LDFLAGS} sup.o sha256.o -o sup

shared: CFLAGS+=-fPIC -fPIE -Wall
shared: LDFLAGS=-fPIC -fPIE -pie -lcrypto
shared: config.h sup


static: CFLAGS+=-DSTATIC=1
static: LDFLAGS=libressl/crypto/libcrypto.a -static-libgcc
static: config.h sup

test: CC=colorgcc
test: CFLAGS+=--std=gnu99
test: LDFLAGS=-lcrypto -lm
test: test.o sha256.o
	${CC} ${LDFLAGS} test.o sha256.o -o test


all: shared

config.h:
	cp config.def.h config.h

sup.o: config.h sup.c
	${CC} ${CFLAGS} -c sup.c -DVERSION=${VERSION}

sup: sup.o
	${CC} ${LDFLAGS} sup.o -o sup

debug: CFLAGS+=-ggdb
debug: sup.o
	${CC} ${LDFLAGS} sup.o -o sup

clean:
	rm -f *.o sup test

mrproper: clean
	rm -f config.h

install:
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f sup ${DESTDIR}${PREFIX}/bin
	-chown ${USER}:${GROUP} ${DESTDIR}/${PREFIX}/bin/sup
	-chmod 4111 ${DESTDIR}${PREFIX}/bin/sup
	mkdir -p ${DESTDIR}${PREFIX}/share/man/man1
	sed s,VERSION,${VERSION}, sup.1 \
	  > ${DESTDIR}${PREFIX}/share/man/man1/sup.1
