#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <optional>
#include <fstream>
#include <iostream>
#include <iomanip>

DWORD g_process_id;
HANDLE g_handle;
uintptr_t g_base;
uintptr_t g_size;
std::unique_ptr<char[]> g_data;

uintptr_t g_register_func = 0x892010;
uintptr_t g_register_native = 0x2AE1AF8;
uintptr_t g_system = 0x2AE17A0;
uintptr_t g_namespaces_start = 0xEDE406;
uintptr_t g_namespaces_end = 0xEDE8AD;
std::vector<uintptr_t> g_namespaces;
uintptr_t g_last = 0x3265E98;

std::vector<std::vector<uintptr_t>> g_dump_hashes;

std::vector<uintptr_t> get_hashes(uintptr_t index)
{
    std::vector<uintptr_t> result;
    while (true)
    {
        //std::cout << "Index: " << std::hex << std::uppercase << index << std::dec << std::nouppercase << "\n";
        if (g_data.get()[index] == '\xC2' && g_data.get()[index + 1] == '\x00' && g_data.get()[index + 2] == '\x00') // nullsub_2
        {
            return result;
        }
        if (index == g_register_native) // namespaces end
        {
            return result;
        }
        if (g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\xB9') // Found hash
        {
            result.push_back(*(uintptr_t*)(g_data.get() + index + 2));
            index += 10;
            continue;
        }
        if (g_data.get()[index] == '\xB9') // Found hash
        {
            result.push_back(*(uint32_t*)(g_data.get() + index + 1));
            std::cout << "B9 found " << std::hex << std::uppercase << index << " " << (uintptr_t) * (uint32_t*)(g_data.get() + index + 1) << std::dec << std::nouppercase << "\n";
            index += 5;
            continue;
        }
        if (g_data.get()[index] == '\xE8')
        {
            if (index + *(int*)(g_data.get() + index + 1) + 5 != g_register_func &&
                index + *(int*)(g_data.get() + index + 1) + 5 != g_register_native)
            {
                std::cout << "get hashes " << std::hex << std::uppercase << index << std::dec << std::nouppercase << "\n";
                std::vector child = get_hashes(index + *(int*)(g_data.get() + index + 1) + 5);
                if (child.size())
                {
                    result.insert(result.end(), child.begin(), child.end());
                }
            }
            index += 5;
            continue;
        }
        if (g_data.get()[index] == '\xE9')
        {
            index += *(int*)(g_data.get() + index + 1) + 5;
            continue;
        }
        if (g_data.get()[index] == '\x4C' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x05' ||
            g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x15' ||
            g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x1D' ||
            g_data.get()[index] == '\x48' && g_data.get()[index + 1] == '\x8D' && g_data.get()[index + 2] == '\x0D')
        {
            index += 7;
            continue;
        }
        index++;
    }
}

void init_namespaces()
{
    for (uintptr_t i = g_namespaces_start; i < g_namespaces_end; i++)
    {
        if (g_data.get()[i] == '\x48' && g_data.get()[i + 1] == '\x8D' && g_data.get()[i + 2] == '\x05')
        {
            g_namespaces.push_back(i + *(int*)(g_data.get() + i + 3) + 7);
            i += 7;
        }
    }
}

int main()
{
    GetWindowThreadProcessId(FindWindowA("sgaWindow", nullptr), &g_process_id);
    g_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, g_process_id);

    HMODULE hMods[1024];
    DWORD cbNeeded;
    EnumProcessModules(g_handle, hMods, sizeof(hMods), &cbNeeded);
    MODULEINFO info;
    GetModuleInformation(g_handle, hMods[0], &info, sizeof(info));
    g_base = (intptr_t)info.lpBaseOfDll;
    g_size = info.SizeOfImage;
    g_data = std::make_unique<char[]>(g_size);
    ReadProcessMemory(g_handle, (LPCVOID)g_base, g_data.get(), g_size, 0);

    std::cout << "Base: " << std::hex << std::uppercase << g_base << std::dec << std::nouppercase << "\n";
    std::cout << "Size: " << std::hex << std::uppercase << g_size << std::dec << std::nouppercase << "\n";

    std::cout << "\n";

    std::cout << "Init namespaces\n";
    init_namespaces();
    //for (int i = 0; i < g_namespaces.size(); i++)
    //{
    //    std::cout << std::hex << std::uppercase << g_namespaces[i] << std::dec << std::nouppercase << "\n";
    //}
    std::cout << "Found " << g_namespaces.size() << " namespaces\n";

    std::cout << "\n";

    std::cout << "getting namespace system\n";
    g_dump_hashes.push_back(get_hashes(g_system));
    for (int i = 0; i < g_namespaces.size(); i++)
    {
        std::cout << "getting namespace " << i << "\n";
        g_dump_hashes.push_back(get_hashes(g_namespaces[i]));
    }
    std::cout << "getting namespace last\n";
    g_dump_hashes.push_back(get_hashes(g_last));

    std::cout << "\n";

    size_t total = 0;
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        total += g_dump_hashes[i].size();
        std::cout << "namespace " << i << ": " << g_dump_hashes[i].size() << "\n";
    }
    std::cout << "total: " << total << "\n";

    std::cout << "\n";

    std::ofstream o("output.txt");
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        o << "namespace " << i << ":\n";
        o << "{\n";
        for (int j = 0; j < g_dump_hashes[i].size(); j++)
        {
            o << "    " << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::uppercase << g_dump_hashes[i][j] << std::dec << std::nouppercase << "\n";
        }
        o << "}\n";
    }
    o << "\n";
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        o << "namespace " << i << ": " << g_dump_hashes[i].size() << "\n";
    }
    o << "total: " << total << "\n";
    o.close();

    o.open("pure_hashes.txt");
    for (int i = 0; i < g_dump_hashes.size(); i++)
    {
        for (int j = 0; j < g_dump_hashes[i].size(); j++)
        {
            o << "0x" << std::setw(16) << std::setfill('0') << std::hex << std::uppercase << g_dump_hashes[i][j] << std::dec << std::nouppercase << "\n";
        }
    }
    o.close();

    std::cout << "done!\n";
    system("pause");
}