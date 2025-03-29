#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void) {
    char key[] = "zBLs%&n)+#";
	unsigned int password, x;
	
	srand(time(NULL));
	
	x = rand() % 10;
	
	if (x == 0) {
		password = key[9] * key[3] * key[5];
	}
	else if (x == 1) {
		password = (key[3] - key[1]) * key[4] * key[8];
	}
	else if (x == 2) {
		password = key[7] * key[5] * key[2];
	}
	else if (x == 3) {
		password = (key[6] + key[0]) * key[6] * key[0] * key[7];
	}
	else if (x == 4) {
		password = key[0] * key[8] * key[2] - key[9];
	}
	else if (x == 5) {
		password = key[7] * key[8] * key[1] + key[9] + key[3];
	}
	else if (x == 6) {
		password = (key[2] - key[8]) * key[3] * key[9] * key[5];
	}
	else if (x == 7) {
		password = key[9] * key[2] * key[0];
	}
	else if (x == 8) {
		password = (key[9] - key[2]) * key[5] * key[3] * key[1];
	}
	else if (x == 9) {
		password = key[8] * key[0] * key[4];
	}
	
	printf("%d\n", password);
	
	return EXIT_SUCCESS;
}