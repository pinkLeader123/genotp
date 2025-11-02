CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -I../include -Wall
LDFLAGS ?=

OBJS = otp.o sha1.o user.o
OUT = genotp

all: $(OUT)

$(OUT): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(OUT)
