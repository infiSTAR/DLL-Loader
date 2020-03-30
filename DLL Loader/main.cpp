#define _CRT_SECURE_NO_WARNINGS //prevents building errors
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")

#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <conio.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include "sha512.hpp"
#include "injection.hpp"
#include <ctime>
#include <string>
#include <tchar.h>
#include <urlmon.h>
#include <WinUser.h>
#include <sstream>
#include <random>
#include <strstream>

using namespace std;

loader* loadertools;

std::string salt = "oursalt"; //global varible because don't care didn't ask


BOOL IsAppRunningAsAdminMode()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    // Determine whether the SID of administrators group is enabled in 
    // the primary access token of the process.
    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    // Centralized cleanup for all allocated resources.
    if (pAdministratorsGroup)
    {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    // Throw the error if something failed in the function.
    if (ERROR_SUCCESS != dwError)
    {
        throw dwError;
    }

    return fIsRunAsAdmin;
}


std::string gethwid()
{
    std::string hashedhwid;
    DWORD lVolSerialNbr = 0;
    char sHDSerial[255] = "";
    GetVolumeInformationA("C:\\", 0, 0, &lVolSerialNbr, 0, 0, 0, NULL);
    _ultoa_s(lVolSerialNbr, sHDSerial, 10);
    std::string c(sHDSerial);
    hashedhwid = sha512(c + salt);
    return hashedhwid;
}

class Color
{
public:
    Color(int desiredColor) {
        consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        color = desiredColor;
    }

    friend ostream& operator<<(ostream& ss, Color obj) {
        SetConsoleTextAttribute(obj.consoleHandle, obj.color);
        return ss;
    }
private:
    int color;
    HANDLE consoleHandle;
    /*
    0 = black
    1 = blue
    2 = green
    3 = light blue
    4 = red
    5 = purple
    6 = gold
    7 = white
    */
};

void printlogo()
{

    system("cls");
    std::cout << Color(4) << R"(
   __                 _           
  / /  ___   __ _  __| | ___ _ __ 
 / /  / _ \ / _` |/ _` |/ _ \ '__|
/ /__| (_) | (_| | (_| |  __/ |   
\____/\___/ \__,_|\__,_|\___|_|                                                                              																			                                                                                   
        )";
    cout << "\n";
}

void currenttime()
{
    time_t curr_time;
    curr_time = time(NULL);
    tm* tm_local = localtime(&curr_time);

    cout << Color(7) << "\n[" << tm_local->tm_hour << ":" << tm_local->tm_min << ":" << tm_local->tm_sec << "] ";
}

void ShowConsoleCursor(bool showFlag)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_CURSOR_INFO     cursorInfo;

    GetConsoleCursorInfo(out, &cursorInfo);
    cursorInfo.bVisible = showFlag; // set the cursor visibility
    SetConsoleCursorInfo(out, &cursorInfo);
}

void randomizetitle()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<> distr(0, 51);
    std::string name = "";
    char alphabet[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
    for (int i = 0; i < 15; ++i)
    {
        name = name + alphabet[distr(mt)];
        SetConsoleTitleA(name.c_str());
    }

}

void adminaccess()
{
    if (IsAppRunningAsAdminMode() == TRUE)
    {

    }
    else
    {
        std::cout << Color(4) << "[-] " << Color(7) << "Program NOT running as administrator!";
        Sleep(5000);
        exit(1);
    }
}

void checkupdate()
{
    std::string version = "1.0";

    TCHAR versionurl[] = _T("www.yourtextfile.com/txt");
    TCHAR loaderlocation[] = _T("C:\\loaderversion.txt");
    HRESULT versionresult = URLDownloadToFile(nullptr, versionurl, loaderlocation, 0, nullptr);

    std::ifstream inFile;
    inFile.open("C:\\loaderversion.txt"); //open the input file
    std::stringstream strStream;
    strStream << inFile.rdbuf(); //read the file
    std::string ourstring = strStream.str(); //str holds the content of the file
    inFile.close(); //closes before deletion
    remove("C:\\loaderversion.txt");

    currenttime();
    std::cout << Color(7) << "Checking For Updates";
    Sleep(3000);

    if (ourstring.find(version) != std::string::npos)
    {
        currenttime();
        std::cout << Color(2) << "[+] " << Color(7) << "Loader Fully Updated";
        Sleep(2000);
        printlogo();
    }
    else
    {

        std::cout << Color(4) << "\n[-] " << Color(7) << "A New Loader Is Available\n";
        Sleep(3000);
        TCHAR loaderurl[] = _T("www.yournewloaderdownload.com/exe");
        TCHAR loaderlocation[] = _T("loader.exe");
        HRESULT loaderresult = URLDownloadToFile(nullptr, versionurl, loaderlocation, 0, nullptr);
        std::cout << Color(2) << "[+] " << Color(7) << "Downloading latest loader...\n";
        Sleep(9000);
        exit(1);
    }
}

void getkey()
{
    TCHAR keysurl[] = _T("www.everybodyskeys.com/txt");
    TCHAR keyslocation[] = _T("C:\\keys.txt");
    HRESULT keyresult = URLDownloadToFile(nullptr, keysurl, keyslocation, 0, nullptr);


    std::ifstream inFilekeys;
    inFilekeys.open("C:\\keys.txt"); //open the input file
    std::stringstream strStreamkeys;
    strStreamkeys << inFilekeys.rdbuf(); //read the file
    std::string keystrings = strStreamkeys.str(); //str holds the content of the file
    inFilekeys.close(); //closes before deletion
    remove("C:\\keys.txt");

    std::string hwid = gethwid();

    std::string accesskey;
    std::string hashedaccesskey;
    std::string fullkey;

    currenttime();
    std::cout << Color(7) << "Welcome " << Color(4) << getenv("USERNAME");
    Sleep(2000);
    ShowConsoleCursor(true);
    currenttime();
    std::cout << Color(7) << "Enter Key:";
    cin >> accesskey;
    hashedaccesskey = sha512(accesskey + salt);
    fullkey = sha512(hwid + hashedaccesskey); //IMPORTANT

    if (keystrings.find(fullkey) != std::string::npos)
    {
        std::cout << Color(2) << "[+] " << Color(7) << "Key Accepted!";
        Sleep(1000);
    }
    else
    {
        std::cout << Color(4) << "[-] " << Color(7) << "Invalid Key or Invalid HWID";
        ofstream myfile("hwid.txt");
        if (myfile.is_open())
        {
            myfile << gethwid();
            myfile.close();
        }
        Sleep(9000);
        exit(1);
    }
}

void injectbarbie()
{
    printlogo();
    std::cout << Color(2) << "[+] " << Color(7) << "Injecting...\n";
    TCHAR dllurl[] = _T("www.ourdll.com/ourdll.dll");
    TCHAR dlllocation[] = _T("C:\\ourdll.dll");
    HRESULT dllresult = URLDownloadToFile(nullptr, dllurl, dlllocation, 0, nullptr);
    loadertools->manualmap();
    Sleep(3000);
    remove("C:\\ourdll.dll");
    std::cout << Color(2) << "[+] " << Color(7) << "Injected Successfully";
    Sleep(9000);
    exit(1);
}

void injection()
{
    std::string option;
    printlogo();
    cout << Color(7) << "Now choose an option\n";
    currenttime();
    cout << Color(7) << "1 - Barbie as the Island Princess - Beta";
    cout << "\n >>";
    cin >> option;

    if (option == "1")
    {
        injectbarbie();
    }
    else
    {
        exit(1);
    }
}


int main()
{
    ShowConsoleCursor(false);
    randomizetitle();
    printlogo();
    Sleep(800);
    adminaccess();
    checkupdate();
    getkey();
    injection();
}

/*
Salt Workflow:

1) Get Harddrive Fingerprint and hash it
2) Get The Serial Code And Hash It
3) Take Hashed HWID and Hashed Key And Hash It
4) Compare Hashed Key with Downloaded List

*/