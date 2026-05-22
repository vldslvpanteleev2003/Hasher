#include <windows.h>
#include <iomanip>
#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <sstream>
#include <WinTrust.h>
#include <SoftPub.h>

void static CopyToClipboard(const std::wstring& text)
{
    if (!OpenClipboard(NULL))
        return;

    EmptyClipboard();

    HGLOBAL hGlob = GlobalAlloc(
        GMEM_MOVEABLE,
        (text.size() + 1) * sizeof(wchar_t)
    );

    if (!hGlob)
    {
        CloseClipboard();
        return;
    }

    memcpy(
        GlobalLock(hGlob),
        text.c_str(),
        (text.size() + 1) * sizeof(wchar_t)
    );

    GlobalUnlock(hGlob);

    SetClipboardData(
        CF_UNICODETEXT,
        hGlob
    );

    CloseClipboard();
}

void static OpenVirusTotal(const std::wstring &hash)
{
    std::wstring url = L"https://www.virustotal.com/gui/file/" + hash;

    HINSTANCE result = ShellExecuteW(
        NULL,
        L"open",
        url.c_str(),
        NULL,
        NULL,
        SW_SHOWNORMAL
    );

    if ((INT_PTR)result <= 32)
    {
        MessageBoxW(
            NULL,
            L"Failed to open browser",
            L"Error",
            MB_OK
        );

        exit(1);
    }
}

void static CheckSignature(const wchar_t* filepath)
{
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filepath;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);

    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;

    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG status = WinVerifyTrust(
        NULL,
        &policyGUID,
        &trustData
    );

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(
        NULL,
        &policyGUID,
        &trustData
    );

    if (status == ERROR_SUCCESS)
    {
        MessageBoxW(
            NULL,
            L"Signature VALID",
            L"Signature",
            MB_OK
        );
    }
    else if (status == TRUST_E_NOSIGNATURE)
    {
        MessageBoxW(
            NULL,
            L"File is UNSIGNED",
            L"Signature",
            MB_OK
        );
    }
    else
    {
        MessageBoxW(
            NULL,
            L"Signature INVALID",
            L"Signature",
            MB_OK
        );
    }
}

std::wstring static sha256(const wchar_t* filepath)
{
    std::ifstream file(filepath, std::ios::binary);

    if (!file)
    {
        MessageBoxW(NULL, reinterpret_cast<LPCWSTR>(L"Failed to open target file"), reinterpret_cast <LPCWSTR>(L"Error"), MB_DEFBUTTON1);
        exit(1);
    }

    BCRYPT_ALG_HANDLE AlgorithmH = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&AlgorithmH, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, reinterpret_cast <LPCWSTR>(L"Error to open Alogrithm provider"), reinterpret_cast <LPCWSTR>(L"Error"), MB_DEFBUTTON1);
        exit(1);
    }

    BCRYPT_HASH_HANDLE phHash = NULL;
    DWORD objectSize = 0;
    DWORD cbResult = 0;

    status = BCryptGetProperty(AlgorithmH, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, reinterpret_cast <LPCWSTR>(L"Error to get property"), reinterpret_cast <LPCWSTR>(L"Error"), MB_DEFBUTTON1);
        exit(1);
    }

    std::vector<UCHAR> hashObject(objectSize);

    status = BCryptCreateHash(AlgorithmH, &phHash, hashObject.data(), hashObject.size(), NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, reinterpret_cast <LPCWSTR>(L"Error to create hash"), reinterpret_cast <LPCWSTR>(L"Error"), MB_DEFBUTTON1);
        exit(1);
    }
    
    constexpr size_t CHUNK_SIZE = 65536;

    std::vector<uint8_t> buffer(CHUNK_SIZE);

    while (file)
    {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        std::streamsize bytesRead = file.gcount();

        if (bytesRead <= 0)
            break;

        status = BCryptHashData(phHash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(bytesRead), 0);  
        if (!BCRYPT_SUCCESS(status))
        {
            MessageBoxW(NULL, reinterpret_cast <LPCWSTR>(L"Unsuccessful hashing"), reinterpret_cast <LPCWSTR>(L"Error"), MB_DEFBUTTON1);
            exit(1);
        }
    }

    unsigned char hash[32];

    status = BCryptFinishHash(phHash, hash, sizeof(hash), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, reinterpret_cast < LPCWSTR>(L"Error to finish hash"), reinterpret_cast < LPCWSTR>(L"Error"), MB_DEFBUTTON1);
        exit(1);
    }

    std::wstringstream ss;

    for (auto i : hash)
    {
        ss
            << std::hex
            << std::setw(2)
            << std::uppercase
            << std::setfill(L'0')
            << (int)i;
    }

    BCryptDestroyHash(phHash);
    BCryptCloseAlgorithmProvider(AlgorithmH, 0);

    return ss.str();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(),&argc);

    if (argc < 3)
    {
        MessageBoxW(NULL, L"Usage: Hasher.exe -<mode> <file>", L"Warning", MB_OK);
        exit(1);
    }

    std::wstring mode = argv[1];
    wchar_t* filepath = argv[2];

    if (mode == L"-h")
    {
        std::wstring hash = sha256(filepath);
        CopyToClipboard(hash);
    }
    else if (mode == L"-vt")
    {
        std::wstring hash = sha256(filepath);
        OpenVirusTotal(hash);
    }
    else if (mode == L"-s")
    {
        CheckSignature(filepath);
    }
    else
    {
        MessageBoxW(NULL, L"Usage: Hasher.exe -<mode> <file>", L"Warning", MB_OK);
    }

    LocalFree(argv);

    exit(1);
}
