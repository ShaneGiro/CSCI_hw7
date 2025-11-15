include header.mak

CC ?= gcc
PROGRAM := mcrypt
OBJS := mcrypt.o KStream.o

.PHONY: all clean test

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBFLAGS)

mcrypt.o: mcrypt.c KStream.h
	$(CC) $(CFLAGS) -c $<

KStream.o: KStream.c KStream.h
	$(CC) $(CFLAGS) -c $<

test: $(PROGRAM)
	./RUN

clean:
	$(RM) $(PROGRAM) $(OBJS) enc.* dec.* txtenc.* txtdec.*
