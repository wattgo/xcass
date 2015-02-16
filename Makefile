XCASS=src
EXAMPLES=simple paging

TARGETS=$(XCASS) $(patsubst %,examples/%,$(EXAMPLES))

all: $(TARGETS)
	@for t in $(TARGETS); do $(MAKE) -C $$t; done
	@echo "Import example keyspace :\n  $$ cqlsh yourhost -f examples/exampledb.cql"

clean:
	@for t in $(TARGETS); do $(MAKE) -C $$t clean; done
