CC=gcc
CFLAGS=-g -Wall
LIBS=-lnghttp2 -lssl -lcrypto -lpthread
DEFS=
INCS=-Isrc
SRCS=src/*.c
OBJS=$(patsubst %.c,%.o,$(wildcard $(SRCS)))
TARGET=avs_test

.PHONY:all clean

%.o:%.c
	$(CC) $(CFLAGS) $(INCS) $(DEFS) -c -o $@ $<

$(TARGET):$(OBJS)
	$(CC) -o $@ $^ $(LIBS)

all:$(TARGET)

clean:
	rm -f $(OBJS)
	rm -f $(TARGET)
