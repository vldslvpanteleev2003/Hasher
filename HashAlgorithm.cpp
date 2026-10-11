#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include "HashAlgorithm.h"


#define chunk_size 65536


//конструктор, сразу инициализируем название алгоритма
HashAlgorithm::HashAlgorithm(std::wstring algorithmName) : m_algorithmName(algorithmName) {};



//функция инициализации всех дескрипторов, данных и т.д.
void HashAlgorithm::initialise()
{
    m_status = BCryptOpenAlgorithmProvider(&m_algorithmH, m_algorithmName.c_str(), nullptr, 0);

    if (!BCRYPT_SUCCESS(m_status))
    {
        MessageBoxW(nullptr, L"Error to open Algorithm provider", L"Error", MB_OK);
        exit(1);
    }

    m_status = BCryptGetProperty(m_algorithmH, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&m_objectSize), sizeof(m_objectSize), &m_cbResult, 0);

    if (!BCRYPT_SUCCESS(m_status))
    {
        MessageBoxW(nullptr, L"Error to get property", L"Error", MB_OK);
        exit(1);
    }

    m_hashObject.resize(m_objectSize);

    m_status = BCryptCreateHash(m_algorithmH, &m_phHash, m_hashObject.data(), static_cast<ULONG>(m_hashObject.size()), nullptr, 0, 0);

    if (!BCRYPT_SUCCESS(m_status))
    {
        MessageBoxW(nullptr, L"Error to create hash", L"Error", MB_OK);
        exit(1);
    }
};



//функция для чтения чанков, делал, чтобы вычисляло хэш одновременно для всех хэшей, кроме ssdeep без повторного чтения файла
void HashAlgorithm::update()
{
    std::ifstream file(m_filePath, std::ios::binary);

    if (!file)
    {
        MessageBoxW(nullptr, L"Failed to open target file", L"Error", MB_OK);

        exit(1);
    }

    std::vector<uint8_t> buffer(chunk_size);

    while (true)
    {
        file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

        std::streamsize bytesRead = file.gcount();

        if (bytesRead <= 0)
            break;

        for (auto& hashObject : m_hashObjects)
        {
            NTSTATUS status = BCryptHashData(hashObject.m_phHash, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(bytesRead), 0);

            if (!BCRYPT_SUCCESS(status))
            {
                MessageBoxW(nullptr, L"Unsuccessful hashing", L"Error", MB_OK);

                exit(1);
            }
        }
    }
}



//функция финализации, здесь уже получаем нужный нам хэщ
void HashAlgorithm::finalise()
{

    m_status = BCryptGetProperty(m_algorithmH, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&m_hashLength), sizeof(m_hashLength), &m_cbResult, 0);

    if (!BCRYPT_SUCCESS(m_status))
    {
        MessageBoxW(nullptr, L"Failed to get hash length", L"Error", MB_OK);
        exit(1);
    }

    std::vector<UCHAR> hash(m_hashLength);

    m_status = BCryptFinishHash(m_phHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
    if (!BCRYPT_SUCCESS(m_status))
    {
        MessageBoxW(NULL, L"Error to finish hash", L"Error", MB_DEFBUTTON1);
        exit(1);
    }

    std::wstringstream ss;

    for (auto i : hash)
    {
        ss << std::hex << std::setw(2) << std::uppercase << std::setfill(L'0') << (int)i;
    }

    m_hashResult = ss.str();

    if (m_algorithmName == BCRYPT_MD5_ALGORITHM)
    {
        m_md5_hash = m_hashResult;
    }
    else if (m_algorithmName == BCRYPT_SHA1_ALGORITHM)
    {
        m_sha1_hash = m_hashResult;
    }
    else if (m_algorithmName == BCRYPT_SHA256_ALGORITHM)
    {
        m_sha256_hash = m_hashResult;
    }

    BCryptDestroyHash(m_phHash);
    BCryptCloseAlgorithmProvider(m_algorithmH, 0);
};