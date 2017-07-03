#pragma once
#ifndef runPE_header_h    // To make sure you don't declare the function more than once by including the header multiple times.
#define runPE_header_h

int RunPortableExecutable(void* Image, char* fake_program);
int runPE_main(void* image, char* fake_program);

#endif