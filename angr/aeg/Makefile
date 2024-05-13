
CROSS = arm-linux-gnueabi-
#CC = $(CROSS)gcc
#LD = $(CROSS)ld
CC = gcc


# Make arm32 binary
all:
	${CC} -O2 -fno-stack-protector -o demo_bin demo_bin.c -z execstack
	${CC} -static -O0 -fno-stack-protector -o pwnmemaybe pwnmemaybe.c -z execstack

