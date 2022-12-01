.DEFAULT_GOAL := both
CFLAGS += -Wall -Wextra -Wpedantic -Waggregate-return -Wwrite-strings -Wvla -Wfloat-equal

encode: encode.o lib/shared_fields.o

decode: decode.o lib/shared_fields.o -lm

.PHONY: both
both: encode
both: decode

.PHONY: debug
debug: CFLAGS += -g
debug: both

.PHONY: clean
clean:
	${RM} decode encode *.o lib/*.o
