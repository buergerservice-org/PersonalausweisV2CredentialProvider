// workflowClient.cpp : Test of workflowLibrary
// Copyright (C) 2021 buergerservice.org e.V. <KeePerso@buergerservice.org>
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#include <iostream>

//for workflowLibrary.lib - copy the newest lib to workflowClient-directory
#include "workflowLibrary.h"
#include <strsafe.h>
#include <AtlBase.h>
#include <atlconv.h>
#include <vector>
#include <wchar.h>


std::wstring strtowstr(std::string s)
{
    std::basic_string<TCHAR> textstr;
    CA2W ca2w(s.c_str(), CP_UTF8);
    textstr = ca2w;
    return textstr;
}



std::string generatepw(int n)
{
    std::string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string number = "0123456789";
    std::string specialchar = "_!?+-$%&";
    int random = 0;
    std::string password = "";
    for (int i = 0; i < n-2; i++)
    {
        random = rand() % alphabet.size();
        password.append(alphabet, random, 1);
    }
    random = rand() % specialchar.size();
    password.append(specialchar, random, 1);
    random = rand() % number.size();
    password.append(number, random, 1);
   
    return password;
}


std::string generatenumber(int n)
{
    std::string number = "0123456789";
    int random = 0;
    std::string x = "";
    for (int i = 0; i < n; i++)
    {
        random = rand() %number.size();
        x.append(number, random, 1);
    }

    return x;
}
/*
std::string generatekey(int n)
{
    unsigned char* k = (unsigned char*)"01234567890123456789012345678901";
    int random = 0;
    for (int i = 0; i < 32; i++)
    {
        random = rand() % 10;
        k[i]= random;
    }

    return x;
}
*/

HKEY OpenKey(HKEY hRootKey, wchar_t* strKey)
{
    HKEY hKey;
    LONG nError = RegOpenKeyEx(hRootKey, strKey, NULL, KEY_ALL_ACCESS, &hKey);

    if (nError == ERROR_FILE_NOT_FOUND)
    {
        std::wcout << "Creating registry key: " << strKey << std::endl;
        nError = RegCreateKeyEx(hRootKey, strKey, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    }

    if (nError) {
        std::cout << "Error: " << nError << " Could not find or create " << strKey << std::endl;
        hKey = 0;
    }
    return hKey;
}

LONG SetVal(HKEY hKey, LPCTSTR lpValue, DWORD data)
{
    LONG nError = RegSetValueEx(hKey, lpValue, NULL, REG_DWORD, reinterpret_cast<BYTE*>(&data), sizeof(data));
    
    if (nError) {
        std::cout << "Error: " << nError << " Could not set registry value: " << (char*)lpValue << std::endl;
    }
    return nError;
}

LONG SetString(HKEY hKey, const std::wstring& valueName,  const std::wstring& data)
{
    std::wcout << "writing value " << valueName << std::endl;
    LONG nError = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ,
        (LPBYTE)(data.c_str()),
        (data.size() + 1) * sizeof(wchar_t));

    if (nError)
        std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
    return nError;
}

LONG SetStringc(HKEY hKey, const std::wstring& valueName, unsigned char * data)
{
    std::wcout << "writing value " << valueName << std::endl;
    LONG nError = RegSetValueExW(
        hKey,
        valueName.c_str(),
        0,
        REG_SZ,
        (LPBYTE)(data),
        (sizeof(data) + 1) * sizeof(unsigned char));

    if (nError)
        std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
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

    if (nError)
        std::cout << "Error: " << nError << " Could not set registry string " << std::endl;
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

    for (int i = 0; i < 256; i++)
    {
        data[i] = sstring[i];
    }

    retdata = CW2A(data);
    return retdata;
}

wchar_t * GetString2(HKEY hKey, LPCTSTR lpValue)
{
    WCHAR sstring[128];
    DWORD dwBufferSize = 0;
    dwBufferSize = sizeof(sstring);
    wchar_t* data = new wchar_t[128];
    std::string retdata = "";

    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, NULL, (unsigned char*)sstring, &dwBufferSize);

    if (nError) return (wchar_t *)"error" ;
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

unsigned char * GetStringc(HKEY hKey, LPCTSTR lpValue)
{
    unsigned char sstring[128];
    DWORD dwBufferSize = 0;
    dwBufferSize = sizeof(sstring);

    LONG nError = RegQueryValueEx(hKey, lpValue, NULL, NULL, (unsigned char*)&sstring, &dwBufferSize);
    if (nError) return (unsigned char *)"error";
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


int main(int argc, char** argv)
{
    std::string PINstring = "";
    std::string outputstring = "";
    std::basic_string<TCHAR> textstr;
    std::locale::global(std::locale("German_germany.UTF-8"));
    int userpasswordlen = 0;

    srand(time(NULL));

    if (argc < 3)
    {
        std::cerr <<
            "Usage: setuserregistry username keyhash <optional>userpassword\n" <<
            "   for example with userpassword\n" <<
            "   setuserregistry user1 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx geheim\n" <<
            "   or without userpassword the userpassword is generated and shown\n" 
            << std::endl;
        return EXIT_FAILURE;
    }

    std::string username = argv[1];
    std::cout << "username = " << username << std::endl;
    //int workflownrint = std::stoi(workflownrstring, nullptr);
    //std::cout << "workflownr= " << workflownrint << std::endl;

    std::string keyhash = argv[2];
    std::cout << "keyhash = " << keyhash << std::endl;


    std::string userpassword = "";
    if (argc < 4) //no password -> generate
    {
        userpassword = generatepw(8);
        std::cout << "userpassword = " << userpassword << std::endl;
    }
    else
    {
        userpassword = argv[3];
        std::cout << "userpassword = " << userpassword << std::endl;
    }
    userpasswordlen = userpassword.length();
    std::cout << "userpasswordlength= " << userpasswordlen << std::endl;

    //instantiate a new workflowclass
    workflowLibrary::workflow wf;


    std::string inputstr = userpassword;
    // test openssl -------------------------------------------


    //------------------------
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

     /* A 256 bit key */
    //unsigned char* key = (unsigned char*)"01234567890123456789012345678901";
    std::string outputk = generatenumber(32);
    std::cout << "passwordkey= " << outputk << std::endl;
    unsigned char* pwkey = (unsigned char*)malloc(sizeof(unsigned char) * outputk.size());
    memcpy((char*)pwkey, outputk.c_str(), outputk.size());

    /* A 128 bit IV */
    //unsigned char* iv = (unsigned char*)"0123456789012345";
    std::string outputi = generatenumber(16);
    std::cout << "passwordiv= " << outputi << std::endl;
    unsigned char* pwiv = (unsigned char*)malloc(sizeof(unsigned char) * outputi.size());
    memcpy((char*)pwiv, outputi.c_str(), outputi.size());

    /* Message to be encrypted */
    //unsigned char* input = (unsigned char*)"The quick brown fox jumps over the lazy dog";
    unsigned char* input = (unsigned char*)malloc(sizeof(unsigned char) * inputstr.size());
    memcpy((char*)input, inputstr.c_str(), inputstr.size());
    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = wf.encrypt(input, strlen((char*)input), pwkey, pwiv, ciphertext);

    std::cout << "ciphertext_len is:" << ciphertext_len << std::endl;

    /* Do something useful with the ciphertext here */
    //printf("Ciphertext is:\n");
    wf.BIO_dump_fp_wrap(stdout, (const char*)ciphertext, ciphertext_len);
    //std::cout << "ciphertext is: " << unsigned(ciphertext) << std::endl;

    /* Decrypt the ciphertext */
    decryptedtext_len = wf.decrypt(ciphertext, ciphertext_len, pwkey, pwiv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s", decryptedtext);
    printf("\n");
    //ciphertext_len = 0;
    //---------------------------------------------------------------------

    wchar_t sxString[256];
    long result;
    WCHAR sAppKeyName[1024];
    DWORD dwType = KEY_ALL_ACCESS;
    DWORD dwBufferSize = 0;
    HKEY hKey = NULL;
    WCHAR suser[1024];
    bool status;
    
    wchar_t  syString[256] = L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\";
    //CA2W un(username.c_str());
    wchar_t * wusername;
    CA2W ca2w(username.c_str(), CP_UTF8);
    wusername = ca2w;
    std::wcout << "wusername= " << wusername << std::endl;
    //StringCchPrintf(syString, ARRAYSIZE(syString), L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\%s", wusername);
    //wchar_t syString[256]= L"SOFTWARE\\buergerservice.org e.V.\\PersonalausweisCredentialProvider\\keys\\";
    wcscat_s(syString, wusername);
    std::wcout << "registrystring= " << syString << "\n" << std::endl;


    hKey = OpenKey(HKEY_LOCAL_MACHINE, syString);
    if (hKey == 0) {
        std::cout << "could not open registryuser" << std::endl;
        return EXIT_FAILURE;
    }
    std::vector<uint8_t> ciphervector;
    LONG serror;
    serror=SetString(hKey, L"keyhash", strtowstr(keyhash));
    if (serror != ERROR_SUCCESS) {
        std::cout << "could not write string keyhash" << std::endl;
        return EXIT_FAILURE;
    }

    for (int i = 0; i < ciphertext_len; i++)
    {
        ciphervector.push_back( ciphertext[i]);
    }
    serror=SetBinary(hKey, "pw", ciphervector);
    if (serror != ERROR_SUCCESS) {
        std::cout << "could not write binary pw" << std::endl;
        return EXIT_FAILURE;
    }
    //wchar_t tmp[128];
    //for (int i = 0; i < 128; i++)
    //{
    //    tmp[i] = ciphertext[i];
    //}
    //std::wcout << "w pw set: " << tmp << std::endl;
    //SetString(hKey, L"pw", tmp);
    serror = SetString(hKey, L"pwkey", strtowstr(outputk));
    if (serror != ERROR_SUCCESS) {
        std::cout << "could not write string pwkey" << std::endl;
        return EXIT_FAILURE;
    }
    serror = SetString(hKey, L"pwiv", strtowstr(outputi));
    if (serror != ERROR_SUCCESS) {
        std::cout << "could not write string pwiv" << std::endl;
        return EXIT_FAILURE;
    }
    serror = SetVal(hKey, L"pwx", DWORD(userpasswordlen));
    if (serror != ERROR_SUCCESS) {
        std::cout << "could not write value pwx" << std::endl;
        return EXIT_FAILURE;
    }
    //SetVal(hKey, L"pwlen", ciphertext_len);
    //std::cout << "strlen ciphertext= " << strlen((char*)ciphertext) << "\n" << std::endl;
    //SetVal(hKey, L"pwc", sizeof((char*)ciphertext));
    userpasswordlen = 0;
    //--------------------------------------------------------------------------
    //testread
    std::cout << "--------------------------------------------------------------\n\n\n" << std::endl;
    std::cout << "read for test" << std::endl;
    std::string rkh;
    std::string rpw;
    std::string rpk;
    std::string rpiv;
    
    //int plen;
    //plen = GetVal(hKey, L"pwc");
    //std::cout << "strlen read= " << plen << "\n" << std::endl;
    rkh=GetString(hKey, L"keyhash");
    if (rkh =="error") {
        std::cout << "could not read string keyhash" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "keyhash read: " << rkh << std::endl;
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
        std::cout << "could not read binary pw" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "\n" << std::endl;
    std::cout << "encrypted originalpassword" << std::endl;
    wf.BIO_dump_fp_wrap(stdout, (const char*)ciphertext, ciphertext_len);
    std::cout << "from registry" << std::endl;
    wf.BIO_dump_fp_wrap(stdout, (const char*)&(cipherregistry)[0], cipherregistry.size());
    std::cout << "\n" << std::endl;
    //std::cout << "ciphert is: " << unsigned(ciphertext) << std::endl;
    //std::cout << "pw read is: " << unsigned(ciphertextr) << std::endl;
    rpk = GetString(hKey, L"pwkey");
    if (rpk == "error") {
        std::cout << "could not read string pwkey" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "pwkey read: " << rpk << std::endl;
    rpiv = GetString(hKey, L"pwiv");
    if (rpiv == "error") {
        std::cout << "could not read string rpiv" << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "pwiv read: " << rpiv << std::endl;
    int cl = cipherregistry.size();
    std::cout << "password len is: " << cl << std::endl;
    userpasswordlen = int(GetVal(hKey, L"pwx"));
    if (userpasswordlen ==0) {
        std::cout << "could not read val pwx" << std::endl;
        return EXIT_FAILURE;
    }


    if (hKey>0) RegCloseKey(hKey);
    //std::cout << "passwordlength is: " << userpasswordlen << std::endl;

    /* Decrypt the pw */
    //input = (unsigned char*)malloc(sizeof(unsigned char) * rpw.size());
    //memcpy((char*)input, rpw.c_str(), rpw.size());

    pwkey = (unsigned char*)malloc(sizeof(unsigned char) * rpk.size());
    memcpy((char*)pwkey, rpk.c_str(), rpk.size());

    pwiv = (unsigned char*)malloc(sizeof(unsigned char) * rpiv.size());
    memcpy((char*)pwiv, rpiv.c_str(), rpiv.size());

    decryptedtext_len = wf.decrypt(&(cipherregistry)[0], cl, pwkey, pwiv, decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';
    //std::cout << "decyptedlen is: " << decryptedtext_len << std::endl;
    //std::cout << "passwordlen is: " << userpasswordlen << std::endl;
    //unsigned char decrypted[128];
    //for (int i = 0; i < userpasswordlen; i++)
    //{
    //    decrypted[i]=decryptedtext[i];
    //}

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    //printf("%s", decryptedtext);
    //printf("\n");

    decryptedtext[userpasswordlen] = '\0';
    printf("Decrypted text short is:\n");
    printf("%s", decryptedtext);
    printf("\n");

    //wchar_t w[128];
    //for (int i = 0; i < userpasswordlen+1; i++)
    //{
    //    w[i] = decryptedtext[i];
    //}
    //w[userpasswordlen] = '\0';
    //std::wcout << w << std::endl;


    return EXIT_SUCCESS;
}