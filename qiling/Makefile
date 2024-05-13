CROSS = arm-linux-gnueabi-
CC = $(CROSS)gcc
LD = $(CROSS)ld


# Make arm32 binary
all:
	${CC} -z execstack -static -fno-stack-protector -o tcpvuln tcpvuln.c 


