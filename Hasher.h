#pragma once
#include <string>
#include <vector>
#include <cstdint>

static void CopyCopyToClipboard(const std::wstring&);
static void OpenVirusTotal(const std::wstring&);
static void CheckSignature(const wchar_t*);
static struct HashResult calculate_hash(const wchar_t*, std::vector<std::wstring> algorithms);
LRESULT CALLBACK Wndproc(HWND, UINT, WPARAM, LPARAM);
static int ShowHash(HINSTANCE, int, std::wstring sha256_hash, std::wstring ssdepp_hash);
static std::vector<uint8_t> get_file_chunk(std::ifstream& file);
static std::streamsize get_file_size(std::ifstream& file);
void read_chunks(std::wstring filepath, std::vector<struct HashContext>& Contexts);

//результат вычисления всех хэшей, данная структура далее отправляется в буффер для отображения в окнах
struct HashResult
{
    std::wstring md5_hash;
    std::wstring sha1_hash;
    std::wstring sha256_hash;
    std::wstring ssdeep_hash;
};


//данные для вычисления хэша, делал, чтобы паралельно вычислять все хэши
struct HashContext
{
    std::wstring algo;
    BCRYPT_HASH_HANDLE phHash;
    BCRYPT_ALG_HANDLE AlgorithmH;
    NTSTATUS status;
    DWORD objectSize;
    DWORD cbResult;
    std::vector<UCHAR> hashObject;
};