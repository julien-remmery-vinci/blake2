CC = gcc
CFLAGS = -Wall -Wextra -ggdb -Wswitch-enum

TARGET=blk

all: $(TARGET)

blk: main.c blk.h
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)