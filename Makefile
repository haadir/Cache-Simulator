CC = gcc
CFLAGS = -g -Wall -Wextra -Werror -std=c11

csim: csim.c
	$(CC) $(CFLAGS) -o csim csim.c

clean:
	rm -rf csim
