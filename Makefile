CC = gcc
CFLAGS = -Wall -Werror -O2
LIBS =
prefix = $(HOME)

PROG = xpcrypt
OBJS += crypto.o
OBJS += xpcrypt.o

all: $(PROG)

install: $(PROG)
	install -s $(PROG) $(prefix)/bin

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJS): crypto.h

clean:
	$(RM) $(PROG) $(OBJS)

.PHONY: all install clean
