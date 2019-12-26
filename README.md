# x86_RunTimeImports
Simple x86 Runtime Importer

How to use?

1) Create instance:
CRunTime* pRunTime = new CRunTime(); 
                  or
std::shared_ptr<CRunTime> pRunTime = std::make_shared<CRunTime>();

2) Adding function name:
pRunTime->RegisterFunction("User32.dll", "MessageBoxA");

User32.dll - dynamic module with our function

MessageBoxA - our function name

3) Declare our function:

typedef int(__stdcall* MessageBoxA_)(void*, const char*, const char*, DWORD);

4) Call it:

pRunTime->CallFunction<MessageBoxA_>("MessageBoxA")(nullptr, "SRAN' GOSPODNYA", "THIS IS WORKING", MB_ICONWARNING | MB_OK);

4.1) or we can combine 3 and 4 clause:

pRunTime->CallFunction<MessageBoxA_>("User32.dll", "MessageBoxA")(0, "ez 2", 0, 0);





