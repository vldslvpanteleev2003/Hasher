#pragma once
#include <windows.h>
#include <string>
#include <vector>

class HashAlgorithm final
{
	public:
        //аттрибуты класса
        inline static std::wstring m_filePath;
        inline static std::vector<HashAlgorithm> m_hashObjects;

        //результаты всех хэшей
        inline static std::wstring m_md5_hash;
        inline static std::wstring m_sha1_hash;
        inline static std::wstring m_sha256_hash;
        inline static std::wstring m_ssdeep_hash;


        //итоговое значение хэша, результат
        std::wstring m_hashResult;

        //функции класса
        HashAlgorithm(std::wstring algorithmName);
        void initialise();
        void finalise();
        static void update();
        

    private:
        //аттрибуты для вычисления хэша
        std::wstring m_algorithmName;
        BCRYPT_HASH_HANDLE m_phHash{ nullptr };
        BCRYPT_ALG_HANDLE m_algorithmH{ nullptr };
        NTSTATUS m_status{ 0 };
        DWORD m_objectSize{ 0 };
        DWORD m_cbResult{ 0 };
        std::vector<UCHAR> m_hashObject;
        DWORD m_hashLength{ 0 };

};