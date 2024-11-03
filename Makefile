CC = gcc

CFLAGS = -Werror -g

include_dir = include
src_dir = src
bin_dir = bin
sources = $(src_dir)/test.c $(src_dir)/blake2.c
target = $(bin_dir)/test

all: test

test: $(bin_dir)
	$(CC) $(CFLAGS) -I$(include_dir) $(sources) -o $(target)

$(bin_dir):
	mkdir $(bin_dir)

valgrind: test
	valgrind --leak-check=full $(target)

clean:
	rm -rf $(bin_dir)