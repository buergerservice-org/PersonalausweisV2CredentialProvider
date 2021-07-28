

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CPersonalausweisCredential.h"
#include "guid.h"
#include <AtlBase.h>
#include <atlconv.h>
#include <vector>
#include <fstream>      // std::ofstream
#ifdef _WIN32
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <wchar.h>
#else
#include <unistd.h>
#endif
#include <wininet.h>
#pragma comment(lib,"Wininet.lib")
#include "SG_InputBoxLib.h"




bool IsAppRunning(const TCHAR* const executableName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (!_tcsicmp(entry.szExeFile, executableName)) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return false;
}


DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}


BOOL TerminateProcess(DWORD dwProcessId, UINT uExitCode)
{
    DWORD dwDesiredAccess = PROCESS_TERMINATE;
    BOOL  bInheritHandle = FALSE;
    HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    if (hProcess == NULL)
        return FALSE;

    BOOL result = TerminateProcess(hProcess, uExitCode);

    CloseHandle(hProcess);

    return result;
}


std::string generatekey(int n)
{
    std::string number = "0123456789abcdef";
    int random = 0;
    std::string x = "";
    for (int i = 0; i < n; i++)
    {
        random = rand() % number.size();
        x.append(number, random, 1);
    }

    return x;
}

std::wstring strtowstr(std::string s)
{
    std::basic_string<TCHAR> textstr;
    CA2W ca2w(s.c_str(), CP_UTF8);
    textstr = ca2w;
    return textstr;
}

bool LPWToString(std::string& s, const LPWSTR pw, UINT codepage = CP_ACP)
{
    bool res = false;
    char* p = 0;
    int bsz;

    bsz = WideCharToMultiByte(codepage, 0, pw, -1, 0, 0, 0, 0);
    if (bsz > 0) {
        p = new char[bsz];
        int rc = WideCharToMultiByte(codepage, 0, pw, -1, p, bsz, 0, 0);
        if (rc != 0) {
            p[bsz - 1] = 0;
            s = p;
            res = true;
        }
    }
    delete[] p;
    return res;
}


void stringclear(std::string& v)
{
    std::fill(v.begin(), v.end(), 0);
}


HKEY OpenKey(HKEY hRootKey, wchar_t* strKey)
{
    HKEY hKey;
    LONG nError = RegOpenKeyEx(hRootKey, strKey, NULL, KEY_ALL_ACCESS, &hKey);

    //if not exists create
    //if (nError == ERROR_FILE_NOT_FOUND)
    //{
        //cout << "Creating registry key: " << strKey << endl;
        //nError = RegCreateKeyEx(hRootKey, strKey, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    //}

    //Could not find or create
    if (nError) hKey = 0;

    return hKey;
}

HKEY OpenKeyCreate(HKEY hRootKey, wchar_t* strKey)
{
    HKEY hKey;
    LONG nError = RegOpenKeyEx(hRootKey, strKey, NULL, KEY_ALL_ACCESS, &hKey);

    //if not exists create
    if (nError == ERROR_FILE_NOT_FOUND)
    {
        //cout << "Creating registry key: " << strKey << endl;
        nError = RegCreateKeyEx(hRootKey, strKey, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    }

    //Could not find or create
    if (nError) hKey = 0;

    return hKey;
}


LONG SetVal(HKEY hKey, LPCTSTR lpValue, DWORD data)
{
    LONG nError = RegSetValueEx(hKey, lpValue, NULL, REG_DWORD, reinterpret_cast<BYTE*>(&data), sizeof(data));

    return nError;
}

LONG SetString(HKEY hKey, const std::wstring& valueName, const std::wstring& data)
{
    //std::wcout << "writing value " << valueName << std::endl;
    LONG nError = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ,
        (LPBYTE)(data.c_str()),
        (data.size() + 1) * sizeof(wchar_t));

    //if (nError)
        //std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
    return nError;
}

LONG SetStringc(HKEY hKey, const std::wstring& valueName, unsigned char* data)
{
    //std::wcout << "writing value " << valueName << std::endl;
    LONG nError = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ,
        (LPBYTE)(data),
        (sizeof(data) + 1) * sizeof(unsigned char));

    //if (nError)
        //std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
    return nError;
}

//void SetBinary(HKEY hKey, LPCSTR valueName, unsigned char* data)
LONG SetBinary(HKEY hKey, LPCSTR valueName, std::vector<uint8_t>& data)
{
    std::wcout << "writing value " << valueName << std::endl;
    LONG nError = RegSetValueExA(
        hKey,
        valueName,
        0,
        REG_BINARY,
        data.data(),
        (DWORD)data.size());

    //if (nError)
        //std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
    return nError;
}



std::string GetString(HKEY hKey, LPCTSTR lpValue)
{
    WCHAR sstring[1024];
    DWORD dwBufferSize = 0;
    dwBufferSize = sizeof(sstring);
    wchar_t data[256];
    std::string retdata = "";

    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, NULL, (unsigned char*)sstring, &dwBufferSize);

    if (nError) return "error";
    //if (nError == ERROR_FILE_NOT_FOUND)
        //sstring = L"";
    //else if (nError)
        //cout << "Error: " << nError << " Could not get registry value " << (char*)lpValue << endl;

    for (int i = 0; i < 256; i++)
    {
        data[i] = sstring[i];
    }

    retdata = CW2A(data);
    return retdata;
}

wchar_t* GetString2(HKEY hKey, LPCTSTR lpValue)
{
    WCHAR sstring[128];
    DWORD dwBufferSize = 0;
    dwBufferSize = sizeof(sstring);
    wchar_t* data = new wchar_t[128];
    std::string retdata = "";

    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, NULL, (unsigned char*)sstring, &dwBufferSize);

    if (nError) return (wchar_t*)"error";
    //if (nError == ERROR_FILE_NOT_FOUND)
        //sstring = L"";
    //else if (nError)
        //cout << "Error: " << nError << " Could not get registry value " << (char*)lpValue << endl;

    for (int i = 0; i < 128; i++)
    {
        data[i] = sstring[i];
    }

    //retdata = CW2A(data);
    return data;
}

unsigned char* GetStringc(HKEY hKey, LPCTSTR lpValue)
{
    unsigned char sstring[128];
    DWORD dwBufferSize = 0;
    dwBufferSize = sizeof(sstring);

    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, NULL, (unsigned char*)&sstring, &dwBufferSize);
    if (nError) return (unsigned char*)"error";
    return sstring;
}


LONG GetBinary(HKEY hKey, LPCSTR lpValue, std::vector<uint8_t>& data)
{
    DWORD dwType = REG_BINARY;

    DWORD size = 0;
    LONG ret = RegQueryValueExA(hKey, lpValue, NULL, NULL, NULL, &size);
    if (ret) return 0;
    data.resize(size);
    ret = RegQueryValueExA(hKey, lpValue, NULL, NULL, data.data(), &size);
    if (ret) return 0;
    data.resize(size);
    return ret;
}



DWORD GetVal(HKEY hKey, LPCTSTR lpValue)
{
    DWORD data;
    DWORD size = sizeof(DWORD);
    DWORD type = REG_DWORD;
    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, &type, (LPBYTE)&data, &size);
    if (nError) return 0;
    //if (nError == ERROR_FILE_NOT_FOUND)
    //    data = 0; // The value will be created and set to data next time SetVal() is called.
    //else if (nError)
        //cout << "Error: " << nError << " Could not get registry value " << (char*)lpValue << endl;

    return data;
}


std::string randomnr(int size)
{
    srand((unsigned)time(NULL));
    int u = (double)rand() / (RAND_MAX + 1) * (2000000000 - 1000000) + 1000000;
    std::string su = std::to_string(u);
    return su;
}


CPersonalausweisCredential::CPersonalausweisCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    credentialready = false;
    
}

CPersonalausweisCredential::~CPersonalausweisCredential()
{
    //Terminate AusweisApp2
    system("taskkill /f /im AusweisApp2.exe");

    //if (TerminateProcess(pi.hProcess, 0))
    //{
        //std::cout << "AusweisApp2 terminated\n\n" << std::endl;
    //}
    //else
    //{
    //    
    //}
    
    pszUserName=L"0000000000000000";
    pszPassword=L"0000000000000000";
    PINstring = "0000000000000000";

    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);


    DllRelease();
}


std::string CPersonalausweisCredential::startAusweisApp2()
{
    std::basic_string<TCHAR> strText;
    HWND hwndOwner = nullptr;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }

    //search AusweisApp2 in registry
    //HKEY currentKey;
    //TCHAR name[1024];
    std::string namestr;
    //DWORD dwSize = 1024, dwIdx = 0;
    long result;
    //FILETIME fTime;

    //long lResult = ERROR_SUCCESS;
    DWORD dwType = KEY_ALL_ACCESS;
    DWORD dwBufferSize = 0;
    HKEY hUninstKey = NULL;
    //HKEY hAppKey = NULL;
    WCHAR sAppKeyName[1024];
    //WCHAR sSubKey[1024];
    WCHAR slastInstallRoot[1024];

    //std::cout << "open registry" << std::endl;
    result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Governikus GmbH & Co. KG\\AusweisApp2", 0, KEY_READ, &hUninstKey);
    if (result != ERROR_SUCCESS)
    {
        //std::cout << "cant open registry" << std::endl;
        log = log.append(L"cant open registry\n");
        strText = L"cant open registry\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
       
        return "e1";
    }
    else
    {
        //The installation path has been verified, now need to start looking for the correct program to uninstall
        //std::cout << "registry found - searching" << std::endl;
        dwBufferSize = sizeof(sAppKeyName);

        // wsprintf(sSubKey, L"%s\\%s", L"SOFTWARE\\WOW6432Node\\Governikus GmbH & Co. KG\\AusweisApp2", sAppKeyName);
        //if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, sSubKey, 0, KEY_READ, &hAppKey) != ERROR_SUCCESS)
        //{
        //    log = log.append(L"cant open regkey\n");
        //    RegCloseKey(hAppKey);
        //    RegCloseKey(hUninstKey);
        //    return false;
        //}

        dwBufferSize = sizeof(slastInstallRoot);
        //if (RegQueryValueEx(hAppKey, L"lastInstallRoot", NULL,
        if (RegQueryValueEx(hUninstKey, L"lastInstallRoot", NULL,
            &dwType, (unsigned char*)slastInstallRoot, &dwBufferSize) == ERROR_SUCCESS)
        {
            log = log.append(L"lastInstallRoot found\n");
        }
        else {
            //std::cout << "lastInstallRoot not found." << std::endl;
            log = log.append(L"lastInstallRoot not found\n");
            strText = L"registry lastInstallRoot not found.\n";
            ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            
            return "e2";
        }

        //RegCloseKey(hAppKey);

    }
    RegCloseKey(hUninstKey);



    //LPTSTR szCmdline = _tcsdup(TEXT("\"C:\\Program Files (x86)\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    //std::string strCmdline;
    //strCmdline = std::string(szCmdline);
    //std::wcout << szCmdline << std::endl;
    char buffer1[] = "\"";
    char buffer2[1024];
    char buffer3[] = "AusweisApp2.exe\"  --ui websocket --port 24727";
    for (int i = 0; i < 1024; i++)
    {
        buffer2[i] = slastInstallRoot[i];
    }
    strcat_s(buffer2, 1024, buffer3);
    strcat_s(buffer1, 1024, buffer2);
    //std::cout << buffer1 << std::endl;
    wchar_t text_wchar[1024];
    for (int i = 0; i < strlen(buffer1); i++)
    {
        text_wchar[i] = buffer1[i];
    }
    LPTSTR newCmdline = L"";
    newCmdline = _tcsdup(text_wchar);
    //std::wcout << newCmdline << std::endl;
    //if (newCmdline == L"")
    //{
    //    newCmdline = _tcsdup(TEXT("\"C:\\Program Files (x86)\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    //}
    log = log.append(newCmdline);
    log = log.append(L"\n");
    //ShowMessageWindow(log.c_str(), L"Message");


    //start AusweisApp2
    STARTUPINFO si;
    //PROCESS_INFORMATION pi; now in header
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    //LPTSTR newCmdline = _tcsdup(TEXT("\"C:\\Program Files\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    //LPTSTR szCmdline = _tcsdup(TEXT("\"C:\\Program Files (x86)\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    LPTSTR szCmdline = _tcsdup(TEXT("\"C:\\Program Files\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    //LPTSTR szCmdline = _tcsdup(TEXT("\"..\\Release\\AusweisApp2\\AusweisApp2.exe\"  --ui websocket --port 24727"));
    if (CreateProcess(NULL,   // module name (use command line)
        newCmdline,      // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi) == false)           // Pointer to PROCESS_INFORMATION structure
    {
        //std::cout << "could not start AusweisApp2 in background\n\n" << std::endl;
        log = log.append(L"could not start AusweisApp2\n");
        strText = L"could not start AusweisApp2\n";
        strText.append(newCmdline);
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        
        return "e3";
    }
    else
    {
        //std::cout << "AusweisApp2 started in background\n\n" << std::endl;
        log = log.append(L"AusweisApp2 started\n");
        //ShowMessageWindow(L"AusweisApp2 started", L"Message");
        //if (testmode) {
        //    strText = L"AusweisApp2 started";
        //    ::MessageBox(hwndOwner, strText.c_str(), L"Info", 0);
        //}
        return "started";
    }
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CPersonalausweisCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const* rgcpfd,
    _In_ FIELD_STATE_PAIR const* rgfsp,
    _In_ ICredentialProviderUser* pcpUser,
    _In_ ICredentialProviderEvents* pcpe,
    _In_ UINT_PTR upAdviseContext,
    std::string credkey)
{
    _pcpe = pcpe;
    _upAdviseContext = upAdviseContext;
    if (credkey != "")
    {
        credentialkey = credkey;
    }
    HRESULT hr = S_OK;
    _cpus = cpus;
    log = L"";
    
    lastLoginFailed = false;
    //credentialready = false;
    testmode = false;
    demomode = false;
    

    std::basic_string<TCHAR> strText;
    HWND hwndOwner = nullptr;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }


    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
    
    keypadstring = "";
    certificatestring = "";
    credentialkey = "";
    std::locale::global(std::locale("German_germany.UTF-8"));

    LPOLESTR clsid;
    if (pcpUser != nullptr) {
        pcpUser->GetProviderID(&guidProvider);
        StringFromCLSID(guidProvider, &clsid);
        CoTaskMemFree(clsid);
        _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
    }
    else {
        _fIsLocalUser = true;//CP V1 or Domain
    }
    pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
    

    //-------------------------------------------------------------------
    //check internetconnection
    DWORD dwFlags;
    BOOL bConn = InternetGetConnectedState(&dwFlags, 0);
    if (bConn)
    {
        //It is Connected
    }
    else
    {
        strText = L"internetconnection does not work. please check internet and your firewall! Exiting Credential Provider.\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }


    //-------------------------------------------------------------------
    // start the AusweisApp2
    std::string aresult;
    aresult = startAusweisApp2();
    if (aresult == "e1" || aresult == "e2")
    {
        strText = L"AusweisApp2 could not started. could not open registry HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Governikus GmbH & Co.KG\\AusweisApp2\\lastInstallRoot\nExiting Credential Provider.";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    if (aresult != "started")
    {
        strText = L"AusweisApp2 could not started. please check your AusweisApp2-Installation! Exiting Credential Provider.\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    
    //-------------------------------------------------------------------
    // read userregistry
    HKEY hKey = NULL;
    unsigned char ciphertext[128];
    int ciphertext_len = 0;
    int decryptedtext_len = 0;
    //std::string username = pszUserName;
    wchar_t  syString[256] = L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\";
    //StringCchPrintf(syString, ARRAYSIZE(syString), L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\%s", pszUserName);
    wchar_t* wusername;
    //std::string susername;
    //LPWToString(susername, pszUserName);
    //CA2W ca2w(susername.c_str(), CP_UTF8);
    wusername = pszUserName;
    wcscat_s(syString, wusername);
    
    //std::wcout << "registrystring= " << syString << "\n" << std::endl;
    log = log.append(L"open userregistry");
    log = log.append(syString);
    hKey = OpenKey(HKEY_LOCAL_MACHINE, syString);
    if (hKey == 0) {
        log = log.append(L"could not open registryuser");
        log = log.append(wusername);
        strText = L"could not open registryuser. Exiting Credential Provider.\n";
        strText.append(wusername);
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }

    unsigned char* pwkey;
    unsigned char* pwiv;
    unsigned char decryptedtext[128];
    LONG serror;
    std::string rkh;
    std::string rpw;
    std::string rpk;
    std::string rpiv;
    int userpasswordlen = 0;
    //int plen;
    //plen = GetVal(hKey, L"pwc");
    //std::cout << "strlen read= " << plen << "\n" << std::endl;

    hashkeyfile = GetString(hKey, L"hashkeyfile");
    if (hashkeyfile == "error") {
        hashkeyfile = "";
        log = log.append(L"could not read registryentry hashkeyfile. Exiting Credential Provider.");
        //log = log.append(wusername);
        //strText = L"could not read string logfile\n";
        //strText.append(wusername);
        //::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
        //    MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        //hr = S_FALSE;
        //return hr;
    }
    if (hashkeyfile != "")
    {
        //strText = L"registryentry hashkeyfile found:\n";
        //strText.append(strtowstr(hashkeyfile));
        //strText.append(L"\nUser: ");
        //strText.append(wusername);
        //::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
        //    MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        log = log.append(L"found registryentry hashkeyfile:\n");
        log = log.append(strtowstr(hashkeyfile));
    }



    rkh = GetString(hKey, L"keyhash");
    if (rkh == "error") {
        log = log.append(L"could not read string keyhash");
        log = log.append(wusername);
        strText = L"could not read string keyhash. Exiting Credential Provider.\n";
        strText.append(wusername);
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    

    //std::cout << "keyhash read: " << rkh << std::endl;
    //unsigned char* ciphertextr = new unsigned char[128];
    //unsigned char ciphertextr[128];
    //wchar_t * tmp2 = GetString2(hKey, L"pw");
    //std::wcout << "w pw set: " << tmp2 << std::endl;
    //for (int i = 0; i < 128; i++)
    //{
    //    ciphertextr[i] = tmp2[i];
    //}
    //unsigned char* ciphertextr = new unsigned char[128];
    //std::string ax = "";
    std::vector<uint8_t> cipherregistry;
    serror=GetBinary(hKey, "pw", cipherregistry);
    if (serror != ERROR_SUCCESS) {
        log = log.append(L"could not read binary pw. Exiting Credential Provider.");
        strText = L"could not read binary pw. Exiting Credential Provider.\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    //std::cout << "\n" << std::endl;
    //std::cout << "encrypted originalpassword" << std::endl;
    //wf.BIO_dump_fp_wrap(stdout, (const char*)ciphertext, ciphertext_len);
    //std::cout << "from registry" << std::endl;
    //wf.BIO_dump_fp_wrap(stdout, (const char*)&(cipherregistry)[0], cipherregistry.size());
    //std::cout << "\n" << std::endl;
    //std::cout << "ciphert is: " << unsigned(ciphertext) << std::endl;
    //std::cout << "pw read is: " << unsigned(ciphertextr) << std::endl;
    rpk = GetString(hKey, L"pwkey");
    if (rpk == "error") {
        log = log.append(L"could not read string rpk");
        strText = L"could not read string rpk\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    //std::cout << "pwkey read: " << rpk << std::endl;
    rpiv = GetString(hKey, L"pwiv");
    if (rpiv == "error") {
        log = log.append(L"could not read string rpiv");
        strText = L"could not read string rpiv\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }
    //std::cout << "pwiv read: " << rpiv << std::endl;
    int cl = cipherregistry.size();
    //std::cout << "password len is: " << cl << std::endl;
    userpasswordlen = int(GetVal(hKey, L"pwx"));
    if (userpasswordlen == 0) {
        log = log.append(L"could not read val pwx");
        strText = L"could not read val pwx\n";
        ::MessageBox(hwndOwner, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        hr = S_FALSE;
        return hr;
    }

    if (hKey>0) RegCloseKey(hKey);


    // Decrypt the pw 
    //input = (unsigned char*)malloc(sizeof(unsigned char) * rpw.size());
    //memcpy((char*)input, rpw.c_str(), rpw.size());

    pwkey = (unsigned char*)malloc(sizeof(unsigned char) * rpk.size());
    memcpy((char*)pwkey, rpk.c_str(), rpk.size());

    pwiv = (unsigned char*)malloc(sizeof(unsigned char) * rpiv.size());
    memcpy((char*)pwiv, rpiv.c_str(), rpiv.size());

    //std::cout << "before decrypt\n" << std::endl;
    decryptedtext_len = wf.decrypt(&(cipherregistry)[0], cl, pwkey, pwiv, decryptedtext);

    //std::cout << "behind decrypt\n" << std::endl;

    // Add a NULL terminator. We are expecting printable text
    decryptedtext[userpasswordlen] = '\0';

    // Show the decrypted text
    //printf("Decrypted text is:\n");
    //printf("%s", decryptedtext);
    //printf("\n");

    wchar_t w[128];
    for (int i = 0; i < userpasswordlen+1; i++)
    {
        w[i]= decryptedtext[i];
    }
    //pszPassword = w;
    registrykey = rkh;
    pszPassword = _wcsdup(w);
    log = log.append(L"\n");
    log = log.append(L"the userpassword is: ");
    log = log.append(pszPassword);
    log = log.append(L"\n");
    //log = log.append(L"the userpasswordlen is: ");
    //log = log.append(std::to_wstring( userpasswordlen));
    //log = log.append(L"\n");
    //_rgFieldStrings[SFI_FULLNAME_TEXT] = pszPassword;
    _rgFieldStrings[SFI_FULLNAME_TEXT] = L"";
    //SHStrDupW(w, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
    
    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Personalausweis Credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Personalausweis Credential Provider", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Personalausweis-PIN", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    //if (SUCCEEDED(hr))
    //{
    //    hr = SHStrDupW(L"Test 1134 Checkbox", &_rgFieldStrings[SFI_CHECKBOX]);
    //}
    //if (SUCCEEDED(hr))
    //{
    //    hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    //}
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Erzeuge Personalausweisschlüssel", &_rgFieldStrings[SFI_PERSONALDATA]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Zeige Zertifikat", &_rgFieldStrings[SFI_CERTIFICATE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Zeige Personalausweisschlüssel", &_rgFieldStrings[SFI_HASHKEY]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Info", &_rgFieldStrings[SFI_INFO_LINK]);
    }
    //if (SUCCEEDED(hr))
    //{
    //    hr = SHStrDupW(L"Get personaldata", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    //}
    
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    
    if (SUCCEEDED(hr))
    {
        //PWSTR pszUserName;
        //pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            //wchar_t szString[256];
            //StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            //hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            //CoTaskMemFree(pszUserName);
        }
        else
        {
            //hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    
    if (SUCCEEDED(hr))
    {
        //PWSTR pszPrimarySid;
        //pcpUser->GetStringValue(PKEY_Identity_PrimarySid, &pszPrimarySid);
        //if (pszPrimarySid != nullptr)
        //{
            //wchar_t sxString[256];
            //StringCchPrintf(szString, ARRAYSIZE(szString), L"PrimarySid: %s", pszPrimarySid);
            //hr = SHStrDupW(sxString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            //CoTaskMemFree(pszPrimarySid);
        //}
        //else
        //{
        //    hr = SHStrDupW(L"key is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        //}
    }
    
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"Logon Status is NULL", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }
    

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }
    log = log.append(L"userSID: ");
    log = log.append(std::to_wstring(hr));
    log = log.append(L"\n");

   

    return hr;
}




// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CPersonalausweisCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));

}

// LogonUI calls this to tell us to release the callback.
HRESULT CPersonalausweisCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}



// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CPersonalausweisCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    /*
    HWND hwndOwner = nullptr;
    std::basic_string<TCHAR> strText;
    wchar_t* wbool;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }
    strText = _T("SetSelected.\n");
    strText.append( _T("credentialready: "));
    wbool= credentialready ? L"true" : L"false";
    strText.append(wbool);
    strText.append( _T("\n"));
    strText.append( _T("lastLoginFailed: "));
    wbool = lastLoginFailed ? L"true" : L"false";
    strText.append(wbool);
    strText.append( _T("\n"));
    
    // Display a native Win32 message box
    ::MessageBox(hwndOwner, strText.c_str(), L"Message",
        MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
    */

    if (credentialready && !lastLoginFailed)
    {
        *pbAutoLogon = TRUE;
        //&ICredentialProviderEvents::CredentialsChanged;
    }
    else
    {
        *pbAutoLogon = FALSE;
    }
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CPersonalausweisCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CPersonalausweisCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CPersonalausweisCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CPersonalausweisCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }

       
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CPersonalausweisCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PERSONALDATA;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CPersonalausweisCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CPersonalausweisCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
    
    //return E_NOTIMPL;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CPersonalausweisCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
    
    //return E_NOTIMPL;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CPersonalausweisCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
    
    //return E_NOTIMPL;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CPersonalausweisCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
    
    //return E_NOTIMPL;
}

// Called when the user changes the selected item in the combobox.
HRESULT CPersonalausweisCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
    
    //return E_NOTIMPL;
}

DWORD WINAPI  CreateNoteMessageBox(LPVOID lpParam) {
    ::MessageBox(NULL, (LPCTSTR)lpParam, _T("CPNote"), MB_OK);
    return 0;
}

void CloseNoteMessageBox()
{
    //find Informationwindow in thread and close
    HWND hWndNote = ::FindWindow(NULL, _T("CPNote"));
    if (hWndNote)
    {
        ::PostMessage(hWndNote, WM_CLOSE, 0, 0);
    }
}

void CPersonalausweisCredential::runworkflow(HWND hwndOwner)
{
    //workflow w;
    std::string outputstring = "";
    std::string PIN = "123456";
    int msgboxreturnvalue;
    // STL can be used
    std::basic_string<TCHAR> strText = _T("a service by buergerservice.org e.V.");

    //HWND hwndOwner = nullptr;
    //if (_pCredProvCredentialEvents)
    //{
        //_pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    //}
    HWND hWndMain = hwndOwner;
    std::locale::global(std::locale("German_germany.UTF-8"));

    outputstring = wf.getkeypad();

    //strText=strtowstr(outputstring);
    //msgboxreturnvalue= ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
    //	MB_ICONQUESTION | MB_OK);

    if (outputstring == "e1")
    {
        strText = _T("ERROR - please check AusweisApp2, internetconnection, cardreader and Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e2")
    {
        strText = _T("ERROR - please check your Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONINFORMATION | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e3")
    {
        strText = _T("ERROR - please check your cardreader!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e4")
    {
        strText = _T("ERROR - AusweisApp2-version less than 1.22.* please update!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e5")
    {
        CloseNoteMessageBox();
        strText = _T("Warning - retryCounter of Perso <3, please start a selfauthentication direct with AusweisApp2!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e7")
    {
        CloseNoteMessageBox();
        strText = _T("Error - no cardreader found.");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }

    if (outputstring == "false")
    {
        LPWSTR result = SG_InputBox::GetString2(
            hWndMain,
            L"Message",
            L"Please enter PIN and Confirm this statement:\n Yes i want a key produced from my data.",
            L"");
        LPWToString(PIN, result);

        if (PIN == "")
        {
            strText = _T("ERROR - PIN is empty.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        if (PIN.length() < 6)
        {
            strText = _T("ERROR - PIN is too short.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        if (PIN.length() > 6)
        {
            strText = _T("ERROR - PIN is too long.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }
    }
    else
    {
        strText = _T("Please Confirm this statement:\n Yes i want a key produced from my data.\n(enter your PIN later in your cardreaderkeypad).");
        msgboxreturnvalue = ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONQUESTION | MB_YESNO | MB_SYSTEMMODAL);

        if (msgboxreturnvalue != 6)
        {
            strText = _T("Not confirmed.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        PIN = "123456";
    }
    strText=strtowstr(PIN);
    // Display a native Win32 message box
    //::MessageBox(hWndMain, strText.c_str(), _T("PINInfo"),
    //	MB_ICONINFORMATION | MB_OK);

    //open Informationwindow in thread
    CreateThread(NULL, 0, &CreateNoteMessageBox, _T("selfauthentication is running, please wait...\n(this window closes self-acting)"), 0, NULL);

    outputstring = wf.startworkflow(PIN);

    PIN = "123456";
    if (outputstring == "e1")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check AusweisApp2, cardreader and Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e2")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check your Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e3")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check your cardreader!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e4")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - AusweisApp2-version less than 1.22.* please update!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e5")
    {
        CloseNoteMessageBox();
        strText = _T("Warning - retryCounter of Perso <3, please start a selfauthentication direct with AusweisApp2!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e7")
    {
        CloseNoteMessageBox();
        strText = _T("Error - no cardreader found.");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "" || outputstring.length() < 20)
    {
        //CloseNoteMessageBox();
        strText = _T("ERROR - workflow was not successful!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }

    CloseNoteMessageBox();

    credentialkey = outputstring;
    credentialready = true;

    if (!demomode)
    {
        outputstring = wf.GivenNames;
        outputstring = outputstring.append(", your PersonalausweisCP-Key is ready.\n\n\n");

        //outputstring = outputstring.append("key is: " + credentialkey +"\n");
        outputstring = outputstring.append("for your information: this 4 data from your card are used to produce the key : \nFamilyNames\nGivenNames\nDateOfBirth\nPlaceOfBirth\n\n");

        outputstring = outputstring.append("PersonalData read (for your information):\n\n");
        outputstring = outputstring.append("   AcademicTitle: " + wf.AcademicTitle + "\n");
        outputstring = outputstring.append("   ArtisticName: " + wf.ArtisticName + "\n");
        outputstring = outputstring.append("   BirthName: " + wf.BirthName + "\n");
        outputstring = outputstring.append("   DateOfBirth: " + wf.DateOfBirth + "\n");
        outputstring = outputstring.append("   DocumentType: " + wf.DocumentType + "\n");
        outputstring = outputstring.append("   FamilyNames: " + wf.FamilyNames + "\n");
        outputstring = outputstring.append("   GivenNames: " + wf.GivenNames + "\n");
        outputstring = outputstring.append("   IssuingState: " + wf.IssuingState + "\n");
        outputstring = outputstring.append("   Nationality: " + wf.Nationality + "\n");
        outputstring = outputstring.append("      PlaceOfBirth: " + wf.PlaceOfBirth + "\n");
        outputstring = outputstring.append("   PlaceOfResidence - StructuredPlace:\n");
        outputstring = outputstring.append("      City: " + wf.City + "\n");
        outputstring = outputstring.append("      Country: " + wf.Country + "\n");
        outputstring = outputstring.append("      Street: " + wf.Street + "\n");
        outputstring = outputstring.append("      ZipCode: " + wf.ZipCode + "\n");
    }
    else
    {
        outputstring = wf.ArtisticName;
        outputstring = outputstring.append("HANS, your PersonalausweisCP-Key is ready.\n\n\n");

        //outputstring = outputstring.append("key is: " + credentialkey +"\n");
        outputstring = outputstring.append("for your information: this 4 data from your card are used to produce the key : \nFamilyNames(or Birthname if set)\nGivenNames\nDateOfBirth\nPlaceOfBirth\n\n");

        outputstring = outputstring.append("PersonalData read (for your information):\n\n");
        outputstring = outputstring.append("   AcademicTitle: \n");
        outputstring = outputstring.append("   ArtisticName: \n");
        outputstring = outputstring.append("   BirthName: \n");
        outputstring = outputstring.append("   DateOfBirth: 1975-04-01\n");
        outputstring = outputstring.append("   DocumentType: \n");
        outputstring = outputstring.append("   FamilyNames: MUSTERMANN\n");
        outputstring = outputstring.append("   GivenNames: HANS\n");
        outputstring = outputstring.append("   IssuingState: D\n");
        outputstring = outputstring.append("   Nationality: D\n");
        outputstring = outputstring.append("      PlaceOfBirth: HAMBURG\n");
        outputstring = outputstring.append("   PlaceOfResidence - StructuredPlace:\n");
        outputstring = outputstring.append("      City: BREMEN\n");
        outputstring = outputstring.append("      Country: D\n");
        outputstring = outputstring.append("      Street: HANSESTR. 7\n");
        outputstring = outputstring.append("      ZipCode: 28207\n");
    }
    

    srand((unsigned)time(NULL));
    int u = (double)rand() / (RAND_MAX + 1) * (2000000000 - 1000000) + 1000000;
    std::string su = std::to_string(u);
    wf.personalStyledString = su;
    wf.AcademicTitle = su;
    wf.ArtisticName = su;
    wf.BirthName = su;
    wf.DateOfBirth = su;
    wf.DocumentType = su;
    wf.FamilyNames = su;
    wf.GivenNames = su;
    wf.IssuingState = su;
    wf.Nationality = su;
    wf.PlaceOfBirth = su;
    wf.City = su;
    wf.Country = su;
    wf.Street = su;
    wf.ZipCode = su;


    // OpenSSL (#include <openssl/crypto.h> and link -lcrypto)
    //stringclear(wf.personalStyledString));

    //StringToWString(strText, outputstring);
    CA2W ca2w(outputstring.c_str(), CP_UTF8);
    strText = ca2w;
    outputstring = su;
    //strText = _T("KeePerso Key ready to use.");

    // Display a native Win32 message box
    ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
        MB_ICONINFORMATION | MB_OK | MB_SYSTEMMODAL);

    if(credentialready) 
    {
        //_pcpe->CredentialsChanged(_upAdviseContext);
    }

}



void CPersonalausweisCredential::runworkflow2(HWND hwndOwner)
{
    //workflow w;
    std::string outputstring = "";
    std::string PIN = "123456";
    int msgboxreturnvalue;
    // STL can be used
    std::basic_string<TCHAR> strText = _T("a service by buergerservice.org e.V.");

    //HWND hwndOwner = nullptr;
    //if (_pCredProvCredentialEvents)
    //{
        //_pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    //}
    HWND hWndMain = hwndOwner;
    std::locale::global(std::locale("German_germany.UTF-8"));

    outputstring = wf.getkeypad();

    //strText=strtowstr(outputstring);
    //msgboxreturnvalue= ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
    //	MB_ICONQUESTION | MB_OK);

    if (outputstring == "e1")
    {
        strText = _T("ERROR - please check AusweisApp2, internetconnection, cardreader and Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e2")
    {
        strText = _T("ERROR - please check your Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONINFORMATION | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e3")
    {
        strText = _T("ERROR - please check your cardreader!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e4")
    {
        strText = _T("ERROR - AusweisApp2-version less than 1.22.* please update!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e5")
    {
        CloseNoteMessageBox();
        strText = _T("Warning - retryCounter of Perso <3, please start a selfauthentication direct with AusweisApp2!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e7")
    {
        CloseNoteMessageBox();
        strText = _T("Error - no cardreader found.");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }

    if (outputstring == "false")
    {
        LPWSTR result = SG_InputBox::GetString2(
            hWndMain,
            L"Message",
            L"Please enter PIN and Confirm this statement:\n Yes i want a key produced from my data.",
            L"");
        LPWToString(PIN, result);

        if (PIN == "")
        {
            strText = _T("ERROR - PIN is empty.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        if (PIN.length() < 6)
        {
            strText = _T("ERROR - PIN is too short.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        if (PIN.length() > 6)
        {
            strText = _T("ERROR - PIN is too long.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
            return;
        }
    }
    else
    {
        strText = _T("Please Confirm this statement:\n Yes i want a key produced from my data.\n(enter your PIN later in your cardreaderkeypad).");
        msgboxreturnvalue = ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONQUESTION | MB_YESNO | MB_SYSTEMMODAL);

        if (msgboxreturnvalue != 6)
        {
            strText = _T("Not confirmed.");
            // Display a native Win32 message box
            ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
                MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
            return;
        }

        PIN = "123456";
    }
    strText = strtowstr(PIN);
    // Display a native Win32 message box
    //::MessageBox(hWndMain, strText.c_str(), _T("PINInfo"),
    //	MB_ICONINFORMATION | MB_OK);

    //open Informationwindow in thread
    CreateThread(NULL, 0, &CreateNoteMessageBox, _T("selfauthentication is running, please wait...\n(this window closes self-acting)"), 0, NULL);

    outputstring = wf.startworkflow(PIN);

    PIN = "123456";
    if (outputstring == "e1")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check AusweisApp2, cardreader and Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e2")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check your Personalausweis!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e3")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - please check your cardreader!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e4")
    {
        CloseNoteMessageBox();
        strText = _T("ERROR - AusweisApp2-version less than 1.22.* please update!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e5")
    {
        CloseNoteMessageBox();
        strText = _T("Warning - retryCounter of Perso <3, please start a selfauthentication direct with AusweisApp2!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "e7")
    {
        CloseNoteMessageBox();
        strText = _T("Error - no cardreader found.");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }
    else if (outputstring == "" || outputstring.length() < 20)
    {
        //CloseNoteMessageBox();
        strText = _T("ERROR - workflow was not successful!");
        // Display a native Win32 message box
        ::MessageBox(hWndMain, strText.c_str(), _T("Message"),
            MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
        return;
    }

    CloseNoteMessageBox();

    credentialkey = outputstring;
    //credentialready = true;

    /*
    if (!demomode)
    {
        outputstring = wf.GivenNames;
        outputstring = outputstring.append(", your PersonalausweisCP-Key is ready.\n\n\n");

        //outputstring = outputstring.append("key is: " + credentialkey +"\n");
        outputstring = outputstring.append("for your information: this 4 data from your card are used to produce the key : \nFamilyNames\nGivenNames\nDateOfBirth\nPlaceOfBirth\n\n");

        outputstring = outputstring.append("PersonalData read (for your information):\n\n");
        outputstring = outputstring.append("   AcademicTitle: " + wf.AcademicTitle + "\n");
        outputstring = outputstring.append("   ArtisticName: " + wf.ArtisticName + "\n");
        outputstring = outputstring.append("   BirthName: " + wf.BirthName + "\n");
        outputstring = outputstring.append("   DateOfBirth: " + wf.DateOfBirth + "\n");
        outputstring = outputstring.append("   DocumentType: " + wf.DocumentType + "\n");
        outputstring = outputstring.append("   FamilyNames: " + wf.FamilyNames + "\n");
        outputstring = outputstring.append("   GivenNames: " + wf.GivenNames + "\n");
        outputstring = outputstring.append("   IssuingState: " + wf.IssuingState + "\n");
        outputstring = outputstring.append("   Nationality: " + wf.Nationality + "\n");
        outputstring = outputstring.append("      PlaceOfBirth: " + wf.PlaceOfBirth + "\n");
        outputstring = outputstring.append("   PlaceOfResidence - StructuredPlace:\n");
        outputstring = outputstring.append("      City: " + wf.City + "\n");
        outputstring = outputstring.append("      Country: " + wf.Country + "\n");
        outputstring = outputstring.append("      Street: " + wf.Street + "\n");
        outputstring = outputstring.append("      ZipCode: " + wf.ZipCode + "\n");
    }
    else
    {
        outputstring = wf.ArtisticName;
        outputstring = outputstring.append("HANS, your PersonalausweisCP-Key is ready.\n\n\n");

        //outputstring = outputstring.append("key is: " + credentialkey +"\n");
        outputstring = outputstring.append("for your information: this 4 data from your card are used to produce the key : \nFamilyNames\nGivenNames\nDateOfBirth\nPlaceOfBirth\n\n");

        outputstring = outputstring.append("PersonalData read (for your information):\n\n");
        outputstring = outputstring.append("   AcademicTitle: \n");
        outputstring = outputstring.append("   ArtisticName: \n");
        outputstring = outputstring.append("   BirthName: \n");
        outputstring = outputstring.append("   DateOfBirth: 1975-04-01\n");
        outputstring = outputstring.append("   DocumentType: \n");
        outputstring = outputstring.append("   FamilyNames: MUSTERMANN\n");
        outputstring = outputstring.append("   GivenNames: HANS\n");
        outputstring = outputstring.append("   IssuingState: D\n");
        outputstring = outputstring.append("   Nationality: D\n");
        outputstring = outputstring.append("      PlaceOfBirth: HAMBURG\n");
        outputstring = outputstring.append("   PlaceOfResidence - StructuredPlace:\n");
        outputstring = outputstring.append("      City: BREMEN\n");
        outputstring = outputstring.append("      Country: D\n");
        outputstring = outputstring.append("      Street: HANSESTR. 7\n");
        outputstring = outputstring.append("      ZipCode: 28207\n");
    }
    */

    srand((unsigned)time(NULL));
    int u = (double)rand() / (RAND_MAX + 1) * (2000000000 - 1000000) + 1000000;
    std::string su = std::to_string(u);
    wf.personalStyledString = su;
    wf.AcademicTitle = su;
    wf.ArtisticName = su;
    wf.BirthName = su;
    wf.DateOfBirth = su;
    wf.DocumentType = su;
    wf.FamilyNames = su;
    wf.GivenNames = su;
    wf.IssuingState = su;
    wf.Nationality = su;
    wf.PlaceOfBirth = su;
    wf.City = su;
    wf.Country = su;
    wf.Street = su;
    wf.ZipCode = su;


    // OpenSSL (#include <openssl/crypto.h> and link -lcrypto)
    //stringclear(wf.personalStyledString));

    //StringToWString(strText, outputstring);
    CA2W ca2w(outputstring.c_str(), CP_UTF8);
    strText = ca2w;
    outputstring = su;
    //strText = _T("KeePerso Key ready to use.");

    // Display a native Win32 message box
    //::MessageBox(hWndMain, strText.c_str(), _T("Message"),
    //    MB_ICONINFORMATION | MB_OK | MB_SYSTEMMODAL);

    //if (credentialready)
    //{
    //    _pcpe->CredentialsChanged(_upAdviseContext);
    //}

}

// Called when the user clicks a command link.
HRESULT CPersonalausweisCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    //instantiate a new workflowclass
    //workflowLibrary::workflow wf;
    std::string res = "";
    std::string outputstring = "";
    std::basic_string<TCHAR> strText;
    std::basic_string<TCHAR> result;
    std::basic_string<TCHAR> starttext;
    std::string aresult;
  

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        bool running;
        wchar_t* vrunning;
        DWORD prid;
        bool tprid;
        LONG serror;
        HKEY hKey = NULL;
        unsigned char* pwkey;
        unsigned char* pwiv;
        unsigned char decryptedtext[128];
        std::string rkh;
        std::string rpw;
        std::string rpk;
        std::string rpiv;
        int userpasswordlen = 0;
        wchar_t  syString[256] = L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\";
        wchar_t* wusername;
        //if (_pCredProvCredentialEvents)
        //{
        //    _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
        //}
        

        switch (dwFieldID)
        {
        case SFI_CERTIFICATE:
            //open Informationwindow in thread
            //CreateThread(NULL, 0, &CreateNoteMessageBox, _T("getcertificate is running, please wait...\n(this window closes self-acting)"), 0, NULL);
            outputstring=wf.getcertificate();
            //CloseNoteMessageBox();
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            if (outputstring == "e1" || outputstring == "e3")
            {
                strText = _T("ERROR - please check AusweisApp2, internetconnection, cardreader and Personalausweis! Exiting.");
                // Display a native Win32 message box
                ::MessageBox(hwndOwner, strText.c_str(), L"Message",
                    MB_ICONERROR | MB_OK | MB_SYSTEMMODAL);
                hr = E_INVALIDARG;
                return hr;
            }
            certificatestring = "";
            certificatestring = certificatestring + wf.issuerName +"\n";
            certificatestring = certificatestring + wf.issuerUrl + "\n";
            certificatestring = certificatestring + wf.purpose + "\n";
            certificatestring = certificatestring + wf.subjectName + "\n";
            certificatestring = certificatestring + wf.subjectUrl + "\n";
            certificatestring = certificatestring + wf.termsOfUsage + "\n";
            certificatestring = certificatestring + "validity:\n";
            certificatestring = certificatestring + wf.effectiveDate + "\n";
            certificatestring = certificatestring + wf.expirationDate + "\n";
            strText = strtowstr(certificatestring);

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, strText.c_str(), L"Certificate", 0);

            //_pCredProvCredentialEvents->BeginFieldUpdates();
            //cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            //_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CERTIFICATE, cpfsShow);
            //_pCredProvCredentialEvents->EndFieldUpdates();
            if (testmode) {
                running = IsAppRunning(L"AusweisApp2.exe");
                log = log.append(L"AusweisApp2 running: ");
                vrunning = running ? L"true" : L"false";
                log = log.append(vrunning);
                log = log.append(L"TerminateProcess AusweisApp2 \n");
            }

            system("taskkill /f /im AusweisApp2.exe");

            Sleep(2000);

            if (testmode) {
                running = IsAppRunning(L"AusweisApp2.exe");
                log = log.append(L"AusweisApp2 running: ");
                vrunning = running ? L"true" : L"false";
                log = log.append(vrunning);
                log = log.append(L"start AusweisApp2 \n");
            }

            aresult = startAusweisApp2();
            if (aresult == "e1" || aresult == "e2" || aresult == "e3")
            {
                hr = S_FALSE;
                return hr;
            }

            if (testmode) {
                running = IsAppRunning(L"AusweisApp2.exe");
                log = log.append(L"AusweisApp2 running: ");
                vrunning = running ? L"true" : L"false";
                log = log.append(vrunning);
                log = log.append(L"TerminateProcess \n");
            }

            break;
           

        case SFI_PERSONALDATA:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }


            if (testmode) {
                running = IsAppRunning(L"AusweisApp2.exe");
                log = log.append(L"AusweisApp2 running: ");
                vrunning = running ? L"true" : L"false";
                log = log.append(vrunning);

                strText = _T("Klick Erzeuge Personalausweisschlüssel.");
                strText = strText.append(log);

                // Display a native Win32 message box
                ::MessageBox(hwndOwner, strText.c_str(), L"Info", 0);
            }
            //starttext = L"before we start - please check if AusweisApp2, cardreader, Personalausweis are ready to generate key then press ok\n\nfor your information - this 4 data from your card are used to produce the key : \nFamilyNames\nGivenNames\nDateOfBirth\nPlaceOfBirth\n";
            //starttext = starttext.append(log);
            //::MessageBox(hwndOwner, starttext.c_str(), L"Message", 0);
            runworkflow(hwndOwner);
            
            break;


        case SFI_INFO_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            starttext = L"Personalausweis Credential Provider\nVersion 0.4\nCopyright 2021 buergerservice.org e.V. <KeePerso@buergerservice.org>\nlicense: GNU General Public License\n";
            if (testmode) {
                running = IsAppRunning(L"AusweisApp2.exe");
                vrunning = running ? L"true" : L"false";
                log = log.append(L"AusweisApp2 running: ");
                log = log.append(vrunning);
                log = log.append(L"\nregistrykey: ");
                log = log.append(strtowstr(registrykey));
                log = log.append(L"\ncredentialkey");
                log = log.append(strtowstr(credentialkey));
                log = log.append(L"\n");
                starttext = starttext.append(log);
            }
            ::MessageBox(hwndOwner, starttext.c_str(), L"Info", 0);

            //_pCredProvCredentialEvents->BeginFieldUpdates();
            //cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            //_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_INFO_LINK, cpfsShow);
            //_pCredProvCredentialEvents->EndFieldUpdates();

            break;

        case SFI_HASHKEY:

            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }
            runworkflow2(hwndOwner);
            if (credentialkey == "")
            {
                starttext = L"Der Personalausweisschlüssel ist nicht vorhanden - bitte erzeugen.\n";
                starttext = starttext.append(L"\n");
                ::MessageBox(hwndOwner, starttext.c_str(), L"Info", 0);
            }
            else
            {
                starttext = L"Der erzeugte Personalausweisschlüssel ist:\n";
                if (demomode)
                {
                    res = generatekey(62);
                    starttext = starttext.append(strtowstr(res));
                }
                else
                {
                    starttext = starttext.append(strtowstr(credentialkey));
                    
                    //write hashkeyfile
                    if (hashkeyfile != "")
                    {
                        time_t rawtime;
                        time(&rawtime);
                        std::ofstream ofs;
                        ofs.open(hashkeyfile.c_str(), std::ofstream::out | std::ofstream::app);

                        ofs << "----------------------------------------------------------" << std::endl;
                        ofs << ctime(&rawtime);
                        ofs << credentialkey << std::endl;

                        ofs.close();
                    }

                }
                starttext = starttext.append(L"\n");
                ::MessageBox(hwndOwner, starttext.c_str(), L"Info", 0);

                if (testmode) {
                    running = IsAppRunning(L"AusweisApp2.exe");
                    log = log.append(L"AusweisApp2 running: ");
                    vrunning = running ? L"true" : L"false";
                    log = log.append(vrunning);
                    log = log.append(L"TerminateProcess AusweisApp2 \n");
                }

                system("taskkill /f /im AusweisApp2.exe");

                Sleep(2000);

                if (testmode) {
                    running = IsAppRunning(L"AusweisApp2.exe");
                    log = log.append(L"AusweisApp2 running: ");
                    vrunning = running ? L"true" : L"false";
                    log = log.append(vrunning);
                    log = log.append(L"start AusweisApp2 \n");
                }

                aresult = startAusweisApp2();
                if (aresult == "e1" || aresult == "e2" || aresult == "e3")
                {
                    hr = S_FALSE;
                    return hr;
                }
                Sleep(3000);

                if (testmode) {
                    running = IsAppRunning(L"AusweisApp2.exe");
                    log = log.append(L"AusweisApp2 running: ");
                    vrunning = running ? L"true" : L"false";
                    log = log.append(vrunning);
                    log = log.append(L"TerminateProcess \n");
                }
                
            }

            //_pCredProvCredentialEvents->BeginFieldUpdates();
            //cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            //_pCredProvCredentialEvents->SetFieldState(nullptr, SFI_INFO_LINK, cpfsShow);
            //_pCredProvCredentialEvents->EndFieldUpdates();

            break;

        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}




// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CPersonalausweisCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    std::basic_string<TCHAR> strText;
    HWND hwndOwner = nullptr;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
    }
    
    lastLoginFailed = true;

    if (registrykey == credentialkey)
    {
        _rgFieldStrings[SFI_PASSWORD] = pszPassword;

        // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
        // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
        if (_fIsLocalUser)
        {
            PWSTR pwzProtectedPassword;
            hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
            if (SUCCEEDED(hr))
            {
                PWSTR pszDomain;
                PWSTR pszUsername;
                hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
                if (SUCCEEDED(hr))
                {
                    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                    hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                    if (SUCCEEDED(hr))
                    {
                        // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                        // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                        // as necessary.
                        hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                        if (SUCCEEDED(hr))
                        {
                            ULONG ulAuthPackage;
                            hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                            if (SUCCEEDED(hr))
                            {
                                pcpcs->ulAuthenticationPackage = ulAuthPackage;
                                pcpcs->clsidCredentialProvider = CLSID_CPersonalausweis;
                                // At this point the credential has created the serialized credential used for logon
                                // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                                // that we have all the information we need and it should attempt to submit the
                                // serialized credential.
                                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                            }
                        }
                    }
                    CoTaskMemFree(pszDomain);
                    CoTaskMemFree(pszUsername);
                }
                CoTaskMemFree(pwzProtectedPassword);
            }
        }
        else
        {
            DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

            // First get the size of the authentication buffer to allocate
            if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), nullptr, &pcpcs->cbSerialization) &&
                (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
            {
                pcpcs->rgbSerialization = static_cast<byte*>(CoTaskMemAlloc(pcpcs->cbSerialization));
                if (pcpcs->rgbSerialization != nullptr)
                {
                    hr = S_OK;

                    // Retrieve the authentication buffer
                    if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_CPersonalausweis;

                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                    else
                    {
                        hr = HRESULT_FROM_WIN32(GetLastError());
                        if (SUCCEEDED(hr))
                        {
                            hr = E_FAIL;
                        }
                    }

                    if (FAILED(hr))
                    {
                        CoTaskMemFree(pcpcs->rgbSerialization);
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }
        }
    }
    else
    {
        strText = _T("Fehler - Personalausweisschlüssel passt nicht.\n");
        if (testmode)
        {
            strText.append(L"registrykey= ");
            strText.append(strtowstr(registrykey));
            strText.append(L"\ncredentialkey= ");
            strText.append(strtowstr(credentialkey));
        }
        // Display a native Win32 message box
        ::MessageBox(hwndOwner, strText.c_str(), L"ERROR",
            MB_ICONERROR | MB_OK);
        hr = E_FAIL;
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Falsches Passwort oder Benutzername.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CPersonalausweisCredential::ReportResult(NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    _Outptr_result_maybenull_ PWSTR* ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CPersonalausweisCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    else {
        hr = S_FALSE;
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
    
    /*
    HRESULT hres = E_UNEXPECTED;
    *ppszSid = nullptr;

    if (!sid_.empty())
    {
        hres = SHStrDupW(sid_.c_str(), ppszSid);
    }

    return hres;
    */
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CPersonalausweisCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
