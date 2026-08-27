CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2
CFLAGS  += -Wall -Wextra -Werror
PREFIX  ?= /usr/local

TARGET  := rootlet
LIB     := io.o tty.o
HDR     := io.h tty.h

$(TARGET): rootlet.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -o $@ rootlet.c $(LIB)

sudo: sudo.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -o $@ sudo.c $(LIB)

connect: connect.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -o $@ connect.c $(LIB) -lpthread

$(LIB): %.o: %.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET) sudo connect *.o

.PHONY: install clean
