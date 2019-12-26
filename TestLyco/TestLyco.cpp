#include <iostream>
#include "lib.h"
#include <synchapi.h>

int main()
{
	init_lib();
	Sleep(1000);
	std::cout << "Hello World!\n";
	getchar();
}
