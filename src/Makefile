CFLAGS=-I../include -O2 -Wall -fPIC -DXCASS_VERSION=\"$(VERSION)\" -DCPP_DRIVER_VERSION=\"$(CPP_DRIVER_VERSION)\"
LDFLAGS=-shared

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

$(OBJ): $(SRC)
	$(CC) -c $(CFLAGS) $^

lib: $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $(FULLNAME)

clean:
	@rm -f $(OBJ) $(FULLNAME)
