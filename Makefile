export VERSION=0.4.2
export NAME=libxcass.so
export FULLNAME=$(NAME).$(VERSION)
export CPP_DRIVER_VERSION=1.0.1
export EXAMPLES=simple paging

HEADERS=include
SRC=src
TARGETS=$(SRC) $(patsubst %,examples/%,$(EXAMPLES))

all: $(TARGETS) lib
	@for t in $(TARGETS); do $(MAKE) -C $$t; done
	@echo "\nimport example keyspace :\n  $$ cqlsh yourhost -f examples/exampledb.cql\n"

lib: $(SRC)
	$(MAKE) -C $(SRC) lib

install:
	@echo "installing /usr/local/lib/$(NAME) ..."
	@install -m 644 $(HEADERS)/*.h /usr/local/include/
	@install -m 755 $(SRC)/$(FULLNAME) /usr/local/lib/
	@ln -f -s /usr/local/lib/$(FULLNAME) /usr/local/lib/$(NAME)
	@ldconfig
	@echo "done."

clean:
	@for t in $(TARGETS); do $(MAKE) -C $$t clean; done
