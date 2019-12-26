#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <unordered_map>
#include <stdio.h>


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)


typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
}LDR_MODULE, *PLDR_MODULE;

HMODULE _GetModuleHandle(const wchar_t* szModule)//GetModuleHandle
{
	LoadLibraryW(szModule);

	LDR_MODULE* pModule = NULL;

	__asm
	{
		mov eax, fs: [0x18];    // TEB (Thread Environment Block)
		mov eax, [eax + 0x30]; // PEB (Process Environment Block)
		mov eax, [eax + 0x0C]; // pModule
		mov eax, [eax + 0x0C]; // pModule->InLoadOrderModuleList.Flink
		mov pModule, eax;
	}

	while (pModule->BaseAddress)
	{
		if (_wcsicmp(pModule->BaseDllName.Buffer, szModule) == 0)
		{
			return (HMODULE)pModule->BaseAddress;
		}
		pModule = (LDR_MODULE*)pModule->InLoadOrderModuleList.Flink; // grab the next module in the list
	}

	return NULL;
}

FARPROC WINAPI GetProcAddressR(HMODULE hModule, LPCSTR lpProcName)
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult = NULL;

	if (hModule == NULL || hModule == INVALID_HANDLE_VALUE)
		return NULL;

	// a module handle is really its base address
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		// get the VA of the modules NT Header
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

		pDataDirectory = (PIMAGE_DATA_DIRECTORY)& pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// get the VA of the export directory
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// get the VA for the array of addresses
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// get the VA for the array of name pointers
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// get the VA for the array of name ordinals
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// test if we are importing by name or by ordinal...
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
		{
			// import by ordinal...

			// use the import ordinal (- export ordinal base) as an index into the array of addresses
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

			// resolve the address for this imported function
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			// import by name...
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

				// test if we have a match...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					// use the functions name ordinal as an index into the array of name pointers
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// calculate the virtual address for the function
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					// finish...
					break;
				}

				// get the next exported function name
				uiNameArray += sizeof(DWORD);

				// get the next exported function name ordinal
				uiNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

const wchar_t *GetWC(const char *c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}

struct _Import
{
	const char* ModuleName;
	const char* ImportName;
	DWORD Address;

	_Import(const char* name, const char* importname)
	{
		this->ModuleName = name;
		this->ImportName = importname;

		//fill
		HMODULE ModuleHandle = _GetModuleHandle(GetWC(this->ModuleName));

		printf("%s handle: 0x%X | ", this->ModuleName, ModuleHandle);

		this->Address = (DWORD)GetProcAddressR(ModuleHandle, this->ImportName);

		printf("%s Address: 0x%X\n", this->ImportName, this->Address);
	}
};

class CRunTime
{
public:
	void RegisterFunction(const char* name, const char* importname)
	{
		_Import Import = _Import(name, importname);
		m_Imports[importname] = Import.Address;
	}

	template<typename Fn>
	Fn CallFunction(const char* name, const char* importname)
	{
		DWORD Ordinal = 0x0;

		if (m_Imports[name] != 0x0)
		{
			Ordinal = m_Imports[importname];
		}
		else
		{
			this->RegisterFunction(name, importname);
			Ordinal = m_Imports[importname];
		}

		return (Fn)Ordinal;
	}

	template<typename Fn>
	Fn CallFunction(const char* name)
	{
		DWORD Ordinal = m_Imports[name];
		printf("%s ordinal: 0x%X\n", name, Ordinal);
		return (Fn)Ordinal;
	}

private:
	std::unordered_map<const char*, DWORD> m_Imports;

};


int main()
{
	typedef int(__stdcall* MessageBoxA_)(void*, const char*, const char*, DWORD);

	CRunTime* pRunTime = new CRunTime();

	pRunTime->RegisterFunction("User32.dll", "MessageBoxA");

	pRunTime->CallFunction<MessageBoxA_>("MessageBoxA")(nullptr, "SRAN' GOSPODNYA", "THIS IS WORKING", MB_ICONWARNING | MB_OK);

	getchar();

	pRunTime->CallFunction<MessageBoxA_>("User32.dll", "MessageBoxA")(0, "ez 2", 0, 0);

	getchar();

	return 0;
}
