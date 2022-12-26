#include <Windows.h>

void ShowMessage()
{
	MessageBoxA(NULL, "Dll Injected!", "DLL", MB_OK);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ShowMessage();
		break;
	}

	return TRUE;
}