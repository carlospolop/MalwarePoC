#pragma once
#ifndef Infinite_loop_header_h    // To make sure you don't declare the function more than once by including the header multiple times.
#define Infinite_loop_header_h
#include <stdio.h>
#include <Windows.h>

#define Num_dec_before_thread 20000

DWORD WINAPI pi_dec(LPVOID lpParameter);

#endif