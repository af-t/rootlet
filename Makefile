CC      ?= cc
CFLAGS  ?= -std=gnu11 -O2
CFLAGS  += -Wall -Wextra -Werror
PREFIX  ?= /usr/local

TARGET  := rootlet
SRC     := rootlet.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: install clean
