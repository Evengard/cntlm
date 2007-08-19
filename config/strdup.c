#include <string.h>

int main(int argc, char **argv) {
	return !strcmp("hello", strdup("hello"));
}
