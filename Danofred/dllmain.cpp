#include "includes.h"

void* PatternScan(const wchar_t* moduleName, const char* pattern, const char* mask) {
    MODULEENTRY32W mod_entry;
    mod_entry.dwSize = sizeof(mod_entry);

    const auto h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());

    bool found = false;
    while (Module32NextW(h_snap, &mod_entry))
    { 
        if (!_wcsicmp(mod_entry.szModule, moduleName))
        {
            found = true;
            break;
        }
    }
    if (!found)
        return nullptr;
    BYTE* base = static_cast<BYTE*>(mod_entry.modBaseAddr);
    DWORD size = mod_entry.modBaseSize;

    DWORD maskLength = static_cast<DWORD>(strlen(mask));
    DWORD patternLength = static_cast<DWORD>(strlen(pattern));

    for (DWORD j = 0; j < size - patternLength; ++j) {
        bool found = true;
        for (DWORD k = 0; k < patternLength; ++k) {
            if (mask[k] != '?' && pattern[k] != *(char*)(base + j + k)) {
                found = false;
                break;
            }
        }
        if (found) {
            return base + j;
        }
    }
    return nullptr;
}

const char* pattern = "\x55\x48\x89\xE5\x48\x83\xEC\x30\x48\x89\x4D\x10\x48";
const char* mask = "xxxxxxxxxxxxx";

__int64 __fastcall strcmpKey_hook(char* a1, char* a2)
{
    std::cout << "[~] strcmpKey func called! \n";
    std::cout << "[~] PW entered by you: " << a1 << "\n";
    std::cout << "[~] Correct password: " << a2 << "\n";
    std::cout << "--------------------------------------\n";
    return 1;
}

DWORD WINAPI MainThread(LPVOID lpReserved)
{
    bool init_hook = false;
    std::cout << "\n[+] DLL injected! \n";
    while (!init_hook)
    {
		if (MH_Initialize() != MH_OK) 
		{
			std::cout << "[-] Minhook could not be initialized! \n";
            continue;
		}
        const auto addr = PatternScan(L"keygenMe - 01.exe", pattern, mask);
        if (addr == nullptr)
        {
            std::cout << "[-] Pattern not found!\n";
            continue;
        }
        std::cout << "[~] Func Addr: 0x" << addr << "\n";
        if (MH_CreateHook(addr, &strcmpKey_hook, NULL) != MH_OK)
        {
            std::cout << "[-] Hook could not be created! \n";
            continue;
        }
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            std::cout << "[-] Hook could not be enabled! \n";
            continue;
        }
        std::cout << "[+] Hook setup! \n";
        init_hook = true;
    }
	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}