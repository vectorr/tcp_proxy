EXEC = tcp_proxy
.PHONY: all
all: $(EXEC)

CC ?= gcc
CFLAGS = -std=c11 -Wall -g
LDFLAGS =

OBJS := tcp_proxy.o

deps := $(OBJS:%.o=.%.o.d)

%.o: %.c
	$(CC) $(CFLAGS) -c -MMD -MF .$@.d -o $@ $<

$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) $(EXEC) $(OBJS) $(deps)

-include $(deps)
