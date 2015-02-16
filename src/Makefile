CFLAGS=-I../include -O2 -Wall -fPIC

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

$(OBJ): $(SRC)
	$(CC) -c $(CFLAGS) $^

clean:
	rm -f $(OBJ)
