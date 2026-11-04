CC ?= cc
SRC := ../../../src/connection
CFLAGS := -std=c11 -Wall -Wextra -Werror -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -I$(SRC)
TMP := $(shell mktemp -d 2>/dev/null || echo /tmp/relay-host)

.PHONY: check clean
check:
	python3 run_freeze_wait.py
	python3 run_rx_metadata.py
	python3 run_fatal.py
	python3 run_rtc_alloc.py
	CC="$(CC)" python3 run_ledger_mask.py
	$(CC) $(CFLAGS) test_rescue.c $(SRC)/relay_coord.c -o $(TMP)/test_rescue
	$(TMP)/test_rescue
	$(CC) $(CFLAGS) test_split.c $(SRC)/relay_coord.c -o $(TMP)/test_split
	$(TMP)/test_split
	$(CC) $(CFLAGS) test_coord.c $(SRC)/relay_coord.c -o $(TMP)/test_coord
	$(TMP)/test_coord
	$(CC) $(CFLAGS) test_wire_v3.c -o $(TMP)/test_wire_v3
	$(TMP)/test_wire_v3
	$(CC) $(CFLAGS) test_fast_coord.c $(SRC)/relay_coord.c -o $(TMP)/test_fast_coord
	$(TMP)/test_fast_coord
	$(CC) $(CFLAGS) test_learn.c $(SRC)/relay_coord.c -o $(TMP)/test_learn
	$(TMP)/test_learn
	CC="$(CC)" python3 run_broadcast.py
	python3 check_protocol_sync.py
	CC="$(CC)" python3 run_hid.py
	CC="$(CC)" python3 run_deferred.py
	CC="$(CC)" python3 run_learning_snapshot.py
	CC="$(CC)" python3 run_early_receipt.py
	CC="$(CC)" python3 run_multiblock.py

clean:
	@:
