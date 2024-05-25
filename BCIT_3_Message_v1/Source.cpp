#include <iostream>
#include <filesystem>
#include <windows.h>

int wmain(int argc, wchar_t* argv[])
{
	HWND hwnd = GetConsoleWindow();

	BOOL res1 = ShowWindow(hwnd, SW_HIDE);

	if (argc != 2)
	{
		return 0;
	}

	std::wstring str = std::filesystem::path(argv[0]).filename();

	int res2 = MessageBoxW(hwnd, argv[1], str.c_str(), MB_OK);

	return res2;
}
