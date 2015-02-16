NAME=simple

CFLAGS=-I../../include -O2 -Wall -fPIC
LDFLAGS=-lcassandra

XCASS=$(wildcard ../../src/*.o)

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

$(NAME): $(OBJ)
	$(CC) $(LDFLAGS) $(XCASS) $(OBJ) -o $@

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f $(OBJ) $(NAME)
