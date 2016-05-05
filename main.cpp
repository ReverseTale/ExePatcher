#include <WinSock2.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <experimental/filesystem>

#pragma comment( lib, "Version.lib" )
#pragma comment( lib, "ws2_32.lib" )

struct Patch
{
    uint32_t addr;
    std::vector<uint8_t> bytes;
};

Patch patches[] = {
    // Startup
    { 0x27677C, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },	// 0x67737C
    { 0x276789, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 } },   // 0x677389
    { 0x276794, { 0x90 } },                                 // 0x677394
    { 0x2767CB, { 0x90, 0x90 } },                           // 0x6773CB

    // Xat
    { 0x232244, { 0xB9, 0xFF } },                           // 0x632E44
    { 0x18FD9E, { 0xEB } },                                 // 0x59099E

    // Inet
    { 0x125AF8, { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x90 }},    // 0x5266F8

    // End patches
    { 0x0, {} }
};

const uint8_t restoreInet[] = { 0x50, 0xE8, 0x02, 0xFE, 0xFF, 0xFF };

int main(int argc, char** argv)
{
    char* exe = nullptr;
    std::string ip;

    // Exe path must be set as argument 1
    if (argc > 1)
    {
        exe = argv[1];
    }
    else
    {
        printf("Drag file to this exe or pass as 1st parameter\nPress [ENTER] to exit");
        getchar();
        return 1;
    }

    // Ensure the exe exists
    if (!std::experimental::filesystem::exists(exe))
    {
        std::cout << "Wrong path, file does not exist" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Make a copy if no copy already exists (so that we can restore it)
    std::string backup = std::string(exe) + ".bak";
    if (!std::experimental::filesystem::exists(backup))
    {
        std::experimental::filesystem::copy(std::string(exe), backup);
    }

    // Ask for IP if not passed as 2nd argument
    if (argc <= 2)
    {
        std::cout << "Input a IP (invalid one to restore): ";
        std::cin >> ip;
        getchar();
    }
    else
    {
        ip = argv[2];
    }

    // Convert IP (string) to hexadecimal
    DWORD addr = inet_addr(ip.c_str());
    if (addr != -1)
    {
        // No error, use that IP
        patches[6].bytes[1] = (addr >> 0) & 0xFF;
        patches[6].bytes[2] = (addr >> 8) & 0xFF;
        patches[6].bytes[3] = (addr >> 16) & 0xFF;
        patches[6].bytes[4] = (addr >> 24) & 0xFF;
    }
    else
    {
        // Else, restore the original bytes
        for (int i = 0; i < sizeof(restoreInet); ++i)
        {
            patches[6].bytes[i] = restoreInet[i];
        }
    }

    // Get file version size
    DWORD dwHandle;
    DWORD sz = GetFileVersionInfoSizeA(exe, &dwHandle);
    if (sz == 0)
    {
        std::cout << "Try to run as Admin" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Get file version
    std::vector<unsigned char> buf(sz);
    if (!GetFileVersionInfoA(exe, dwHandle, sz, &buf[0]))
    {
        std::cout << "Try to run as Admin" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Query the version
    VS_FIXEDFILEINFO* pvi;
    sz = sizeof(VS_FIXEDFILEINFO);
    if (!VerQueryValueA(&buf[0], "\\", (LPVOID*)&pvi, (unsigned int*)&sz))
    {
        std::cout << "Try to run as Admin" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Transform to major.minor.hotfix.other
    int major = (pvi->dwFileVersionMS >> 16) & 0xffff;
    int minor = (pvi->dwFileVersionMS) & 0xffff;
    int hotfix = (pvi->dwFileVersionLS >> 16) & 0xffff;
    int other = (pvi->dwFileVersionLS) & 0xffff;

    // Assert it is the same as the one it was thought to be used with
    if (major != 0 || minor != 9 || hotfix != 3 || other != 3057)
    {
        std::cout << "Wrong version" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Open file as read+write+binary, so that it overwrites instead of append
    std::fstream s(exe, std::ios_base::out | std::ios_base::in | std::ios_base::binary);
    if (!s.is_open())
    {
        std::cout << "Can not open file, wrong path, already opened or needs admin rights" << std::endl << "Press [ENTER] to exit" << std::endl;
        getchar();
        return 1;
    }

    // Write all patches
    Patch* patch = &patches[0];
    while (patch->addr != 0x0)
    {
        // Write bytes
        s.seekp(patch->addr, std::ios_base::beg);
        s.write((const char*)&patch->bytes[0], patch->bytes.size());

        // Next patch
        ++patch;
    }

    // Close file and save changes
    s.close();

    // Exit
    std::cout << "DONE!" << std::endl << "Press [ENTER] to exit" << std::endl;
    getchar();

    return 0;
}
