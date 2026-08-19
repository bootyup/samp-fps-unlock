```
void CPlugin::OnSampInitialize() 
{
    uintptr_t address = find_pattern(Samp::Address(), "\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x85\xC0\x74\x00\x8B\x80", "x????x????xxx?xx");
    
    DWORD oldProtect;

    if (VirtualProtect(reinterpret_cast<void*>(address), 4, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        *reinterpret_cast<uint32_t*>(address) = 0x5051FF15;

        VirtualProtect(reinterpret_cast<void*>(address), 4, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 4);
    }
}
```
