#pragma comment(lib, "wintrust.lib")
#include <windows.h>
#include <iomanip>
#include <string>
#include <fstream>
#include <vector>
#include <cstdint>
#include <sstream>
#include <WinTrust.h>
#include <SoftPub.h>
#include <iostream>
#include "ssdeep.h"
#include "Hasher.h"
#include "HashAlgorithm.h"

#define chunk_size 65536

inline void print()
{
    std::cout << "Hello motjer";
}

static std::vector<uint8_t> get_file_chunk(std::ifstream& file) // вынес чтение в файла в отдельную функцию, которая возвращает чанки
{
    std::vector<uint8_t> buffer(chunk_size);

    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    std::streamsize bytes_read = file.gcount();

    buffer.resize(static_cast<size_t>(bytes_read));

    return buffer;
}



static void CopyToClipboard(const std::wstring& text) // копируем в буффер обмена
{
    if (!OpenClipboard(NULL))
        return;

    EmptyClipboard();

    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));

    if (!hGlob)
    {
        CloseClipboard();
        return;
    }

    void* buffer = GlobalLock(hGlob);

    if (!buffer)
    {
        GlobalFree(hGlob);
        CloseClipboard();
        return;
    }

    memcpy(buffer, text.c_str(), (text.size() + 1) * sizeof(wchar_t));

    GlobalUnlock(hGlob);

    SetClipboardData(CF_UNICODETEXT, hGlob);

    CloseClipboard();
}



static void OpenVirusTotal(const std::wstring& hash) // открываем Браузер по умолчанию с VT
{
    std::wstring url = L"https://www.virustotal.com/gui/file/" + hash;

    HINSTANCE result = ShellExecuteW(NULL, L"open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);

    if ((INT_PTR)result <= 32)
    {
        MessageBoxW(NULL, L"Failed to open browser", L"Error", MB_OK);
        exit(1);
    }
}



static void CheckSignature(const wchar_t* filepath) // проверка сигнатуры файла, показывает окно с выводом
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

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;

    WinVerifyTrust(NULL, &policyGUID, &trustData);

    if (status == ERROR_SUCCESS)
    {
        MessageBoxW(NULL, L"Signature VALID", L"Signature", MB_OK);
    }
    else if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN)
    {
        MessageBoxW(NULL, L"File is UNSIGNED", L"Signature", MB_OK);
    }
    else
    {
        MessageBoxW(NULL, L"Signature INVALID", L"Signature", MB_OK);
    }
}



static void calculate_hash(const wchar_t* filepath, std::vector<std::wstring> algorithms) //ключевая функция, рассчитывает все хэши, которые указаны в algorithms
{ 
    HashAlgorithm::m_filePath = filepath;
    HashAlgorithm::m_hashObjects.clear();
    HashAlgorithm::m_hashObjects.reserve(algorithms.size());

    for (const auto& algorithm : algorithms)
    {
        HashAlgorithm::m_hashObjects.emplace_back(algorithm);
        HashAlgorithm& hashObject{ HashAlgorithm::m_hashObjects.back() };
        hashObject.initialise();
    }

    HashAlgorithm::update();

    for (auto& hashObject : HashAlgorithm::m_hashObjects)
    {
        hashObject.finalise();
    }
}



LRESULT CALLBACK Wndproc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) //callback функция, которая вызывается каждый раз при каком то ивенте, вызывается очень часто
{
    switch (uMsg) // фильтруем события
    {

        case WM_CREATE: // когда создается основное окно, то создаем остальные
        {
            CreateWindowExW( //label md5
                0,
                L"STATIC",
                L"MD5:",
                WS_CHILD | WS_VISIBLE,
                20, //расположение x
                33, //расположение y
                60, //размеры x
                20, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //поле с md5
                WS_EX_CLIENTEDGE,
                L"EDIT",
                HashAlgorithm::m_md5_hash.c_str(),
                WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                85, //расположение x
                30, //расположение y
                570, //размеры x
                25, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //кнопка copy md5
                0,
                L"BUTTON",
                L"Copy",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                670, //расположение x
                30, //расположение y
                100, //размеры x
                25, //размеры y
                hwnd,
                reinterpret_cast<HMENU>(1001), //идентификатор класса
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //label sha1
                0,
                L"STATIC",
                L"SHA1:",
                WS_CHILD | WS_VISIBLE,
                20, //расположение x
                63, //расположение y
                60, //размеры x
                20, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //поле с sha1
                WS_EX_CLIENTEDGE,
                L"EDIT",
                HashAlgorithm::m_sha1_hash.c_str(),
                WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                85, //расположение x
                60, //расположение y
                570, //размеры x
                25, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //кнопка copy sha1
                0,
                L"BUTTON",
                L"Copy",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                670, //расположение x
                60, //расположение y
                100, //размеры x
                25, //размеры y
                hwnd,
                reinterpret_cast<HMENU>(1002), //идентификатор класса
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //label sha256
                0,
                L"STATIC",
                L"SHA256:",
                WS_CHILD | WS_VISIBLE,
                20, //расположение x
                93, //расположение y
                60, //размеры x
                20, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //поле с sha256
                WS_EX_CLIENTEDGE,
                L"EDIT",
                HashAlgorithm::m_sha256_hash.c_str(),
                WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                85, //расположение x
                90, //расположение y
                570, //размеры x
                25, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //кнопка copy sha256
                0,
                L"BUTTON",
                L"Copy",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                670, //расположение x
                90, //расположение y
                100, //размеры x
                25, //размеры y
                hwnd,
                reinterpret_cast<HMENU>(1003), //идентификатор класса
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //label ssdeep
                0,
                L"STATIC",
                L"SSDEEP:",
                WS_CHILD | WS_VISIBLE,
                20, //расположение x
                123, //расположение y
                60, //размеры x
                20, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //поле с ssdeep
                WS_EX_CLIENTEDGE,
                L"EDIT",
                HashAlgorithm::m_ssdeep_hash.c_str(),
                WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                85, //расположение x
                120, //расположение y
                570, //размеры x
                25, //размеры y
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //кнопка copy ssdeep
                0,
                L"BUTTON",
                L"Copy",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                670, //расположение x
                120, //расположение y
                100, //размеры x
                25, //размеры y
                hwnd,
                reinterpret_cast<HMENU>(1004), //идентификатор класса
                GetModuleHandleW(nullptr),
                nullptr
            );

            return 0;
        }

        case WM_COMMAND: //включает различные события, в том числе нажатия кнопок
        {
            int id = LOWORD(wParam); //тут размер wParam зависит от платформы, тут это младшая половина бит, это айди класса
            int notification = HIWORD(wParam); //тут это старшая половина бит, это конкретное событие от этого класса, например BN_CLICKED

            if (id == 1001 && notification == BN_CLICKED)
            {
                CopyToClipboard(HashAlgorithm::m_md5_hash);
            }

            if (id == 1002 && notification == BN_CLICKED)
            {
                CopyToClipboard(HashAlgorithm::m_sha1_hash);
            }

            if (id == 1003 && notification == BN_CLICKED)
            {
                CopyToClipboard(HashAlgorithm::m_sha256_hash);
            }

            if (id == 1004 && notification == BN_CLICKED)
            {
                CopyToClipboard(HashAlgorithm::m_ssdeep_hash);
            }

            return 0;
        }

        case WM_DESTROY: // срабатывает когда закрываем окно
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}



static int ShowHash(HINSTANCE hInstance, int nCmdShow)
{
    int width = 800; //ширина основного окна
    int height = 220; //высота основного окна

    int screenWidth = GetSystemMetrics(SM_CXSCREEN); // получаем разрешение экрана
    int screenHeight = GetSystemMetrics(SM_CYSCREEN); // получаем разрешение экрана

    int x = (screenWidth - width) / 2; // получаем расположение для окна по центру экрана
    int y = (screenHeight - height) / 2;

    const wchar_t CLASS_NAME[] = L"HasherWindow"; // имя класса 

    /*
    Регистрируем свой класс окна, ибо нам определить свою callbackk функцию типа WNDPROC
    */
    WNDCLASSW wc{}; //обьявляем класс

    wc.lpfnWndProc = Wndproc; // callback функция типа WNDPROC
    wc.hInstance = hInstance; // текущий дескриптор процесса (вроде)
    wc.lpszClassName = CLASS_NAME;

    RegisterClassW(&wc); //регистрируем класс
    
    /*
    Создаем первое/главное окно
    */
    HWND hwnd = CreateWindowExW(
        0, // доп. стили окна
        CLASS_NAME, 
        L"Hasher", // заголовок окна
        (WS_SYSMENU), //из всех только это опция подходит, добавляет крестик для закрытия приложения
        x, //расположение 
        y, //расположение 
        width, //ширина окна
        height, //высота окна
        nullptr, // HWND - дескриптор родительского окна, тут не нужен ибо сам родительский
        nullptr, // целочисленный id классов, нужен для взаимодействия с конкретным классов при обработке ивентов, пример смотреть выше класс кнопки BUTTON 
        hInstance, // дескриптор модуля EXE
        nullptr // доп. параметры которые можно отправить в callback функцию в параметр LPARAM lParam при создании окна, если дочерний класс учавствует в обработке ивентов, то очень нужный параметр
    );

    if (!hwnd)
        return 1;

    ShowWindow(hwnd, nCmdShow); //показывает окно, если не выставлен параметр WS_VISIBLE

    MSG msg{}; //структура сообщений при ивентах

    while (GetMessageW(&msg, nullptr, 0, 0)) //ждёт и извлекает сообщения из очереди потока, практически непрерывно получает ивенты, как минимум движения мыши. Цикл заканчивается, когда приходит событие WM_QUIT, тогда GetMessageW возвращает 0, а WM_QUIT приходит когда вызывается PostQuitMessage()
    {
        TranslateMessage(&msg); //что то связанное с клавиатурой
        DispatchMessageW(&msg); // передаёт сообщение оконной процедуре WndProc нужного окна -> WndProc(hwnd, msg.message, msg.wParam, msg.lParam)
    }

    return 0;
}



int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) // GUI main
{
    int argc;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argc < 3)
    {
        MessageBoxW(NULL, L"Usage: Hasher.exe -<mode> <file>", L"Warning", MB_OK);
        exit(1);
    }

    std::wstring mode = argv[1];
    wchar_t* filepath = argv[2];

    if (mode == L"-ch") //copy hash
    {
        std::vector<std::wstring> algorithms{ BCRYPT_SHA256_ALGORITHM };
        calculate_hash(filepath, algorithms);
        CopyToClipboard(HashAlgorithm::m_sha256_hash);
    }
    else if (mode == L"-vt") //virus total
    {
        std::vector<std::wstring> algorithms{ BCRYPT_SHA256_ALGORITHM };
        calculate_hash(filepath, algorithms);
        OpenVirusTotal(HashAlgorithm::m_sha256_hash);
    }
    else if (mode == L"-sig") // signature
    {
        CheckSignature(filepath);
    }
    else if (mode == L"-sh") // show hash
    {
        std::vector<std::wstring> algorithms{BCRYPT_MD5_ALGORITHM, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM};
        calculate_hash(filepath, algorithms);
        ssdeep(filepath);
        ShowHash(hInstance, nCmdShow);
    }
    else
    {
        MessageBoxW(NULL, L"Usage: Hasher.exe -<mode> <file>", L"Warning", MB_OK);
    }

    LocalFree(argv);

    return 0;
}