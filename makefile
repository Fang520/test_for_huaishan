CC=gcc
CFLAGS=-g -Wall
LIBS=
DEFS=
INCS=-Iinclude
SRCS=src/*.c main.c
OBJS=$(patsubst %.c,%.o,$(wildcard $(SRCS)))
TARGET=avs_test

.PHONY:all clean

%.o:%.c
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -c -o $@ $<

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all:$(TARGET)

clean:
	rm $(OBJS)
	rm $(TARGET)
