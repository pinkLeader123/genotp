CC ?= $(CROSS_COMPILE)gcc
CFLAGS = -I../include -Wall
OBJS = otp.o sha1.o user.o
OUT = gentop

all: $(OBJS)
	$(CC) $(OBJS) -o $(OUT)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(OUT)
