#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>



int we_want_to_go_there() {
    write(1, "FLAG{make code reacheable again!}\n\n", 35);
}


int main(int argc, char *argv[]) {
	char overflow[256];
    char feeling_lucky[4];
    FILE *fp;

	printf("please pwn me with angr: ");	
	read(0, overflow, 2048);
    fp = fopen("/dev/urandom", "rb");
    if (fp == 0) {
        printf("can't access urandom");
        return -1;
    } else {
        fread((char *)feeling_lucky, 4, 1, fp);
        fclose(fp);
    }

    if ((uint32_t)feeling_lucky == 123456789) {
        we_want_to_go_there();
    }

    
    return 0;

}
