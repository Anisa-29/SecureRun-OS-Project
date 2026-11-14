CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11 -D_GNU_SOURCE -pthread
SRC     = src/main.c src/util.c src/cgroup.c src/compiler.c src/runner.c src/judge.c
OBJ     = $(SRC:.c=.o)

securerun: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

src/%.o: src/%.c src/common.h src/util.h src/cgroup.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f securerun src/*.o

.PHONY: clean
