# Makefile for pgrecyclebin
EXTENSION = pgrecyclebin
MODULE_big = pgrecyclebin
OBJS = pgrecyclebin.o

EXTENSION_VERSION = 1.0
DATA = pgrecyclebin--$(EXTENSION_VERSION).sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Extra warnings encouraged
PG_CFLAGS += -Wall -Wextra -Wno-unused-parameter
