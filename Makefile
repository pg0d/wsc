CC = clang
CFLAGS = -std=c11 -pedantic -Wall -Wextra -g

TARGET = test

SRCS = wsc.c test.c

OBJS = $(SRCS:.c=.o)

test: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: test clean

