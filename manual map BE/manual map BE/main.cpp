#include "mmap.hpp"

int main(int argc, char **argv) { 
	mmap mapper(INJECTION_TYPE::KERNEL);

	if (!mapper.attach_to_process(_xor_("FortniteClient-Win64-Shipping.exe").c_str()))
		return 1;

	if (!mapper.load_dll(_xor_("fn.dll").c_str()))
		return 1;

	if (!mapper.inject())
		return 1;

	Sleep(2000);
	 
	return 0;
}