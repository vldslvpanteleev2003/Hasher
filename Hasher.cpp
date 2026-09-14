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

static std::wstring sha256(const wchar_t* filepath) //ключевая функция, рассчитывает sha256
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
        MessageBoxW(NULL, L"Error to open Alogrithm provider", L"Error", MB_DEFBUTTON1);
        exit(1);
    }

    BCRYPT_HASH_HANDLE phHash = NULL;
    DWORD objectSize = 0;
    DWORD cbResult = 0;

    status = BCryptGetProperty(AlgorithmH, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, L"Error to get property", L"Error", MB_DEFBUTTON1);
        exit(1);
    }

    std::vector<UCHAR> hashObject(objectSize);

    status = BCryptCreateHash(AlgorithmH, &phHash, hashObject.data(), hashObject.size(), NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        MessageBoxW(NULL, L"Error to create hash", L"Error", MB_DEFBUTTON1);
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
        MessageBoxW(NULL, L"Error to finish hash", L"Error", MB_DEFBUTTON1);
        exit(1);
    }

    std::wstringstream ss;

    for (auto i : hash)
    {
        ss << std::hex << std::setw(2) << std::uppercase << std::setfill(L'0') << (int)i;
    }

    BCryptDestroyHash(phHash);
    BCryptCloseAlgorithmProvider(AlgorithmH, 0);

    return ss.str();
}

LRESULT CALLBACK Wndproc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) //callback функция, которая вызывается каждый раз при каком то ивенте, вызывается очень часто
{
    std::wstring* data = reinterpret_cast<std::wstring*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA)); // извлекаем данные после SetWindowLongPtrW

    switch (uMsg) // фильтруем события
    {

        case WM_NCCREATE: //событие самого раннего создания окна
        {
            CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam); // получаем ссылку на структуру

            std::wstring* data = static_cast<std::wstring*>(cs->lpCreateParams); //вытаскиваем данные из lParam

            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(data)); // сохраняем данные для нашего hwnd, позволяет получать данные те же данные при последующих ивентах

            return TRUE;
        }

        case WM_CREATE: // когда создается основное окно, то создаем остальные
        {
            CreateWindowExW( //label sha256
                0,
                L"STATIC",
                L"SHA256:",
                WS_CHILD | WS_VISIBLE,
                20,
                33,
                60,
                20,
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //поле с sha256
                WS_EX_CLIENTEDGE,
                L"EDIT",
                data->c_str(),
                WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
                85,
                30,
                570,
                25,
                hwnd,
                nullptr,
                GetModuleHandleW(nullptr),
                nullptr
            );

            CreateWindowExW( //кнопка
                0,
                L"BUTTON",
                L"Copy",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                670,
                30,
                100,
                25,
                hwnd,
                reinterpret_cast<HMENU>(1001), //идентификатор класса
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
                if (data)
                {
                    CopyToClipboard(*data);
                }
            }
            return 0;
        }

        case WM_DESTROY: // срабатывает когда закрываем окно
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}


static int ShowHash(HINSTANCE hInstance, int nCmdShow, std::wstring hash)
{
    int width = 800; //ширина основного окна
    int height = 150; //высота основного окна

    int screenWidth = GetSystemMetrics(SM_CXSCREEN); // получаем разрешение экрана
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

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
    Создаем первое окно
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
        &hash // доп. параметры которые можно отправить в callback функцию в параметр LPARAM lParam при создании окна, если дочерний класс учавствует в обработке ивентов, то очень нужный параметр
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
        std::wstring hash = sha256(filepath);
        CopyToClipboard(hash);
    }
    else if (mode == L"-vt") //virus total
    {
        std::wstring hash = sha256(filepath);
        OpenVirusTotal(hash);
    }
    else if (mode == L"-sig") // signature
    {
        CheckSignature(filepath);
    }
    else if (mode == L"-sh") // show hash
    {
        std::wstring hash = sha256(filepath);
        ShowHash(hInstance, nCmdShow, hash);
    }
    else
    {
        MessageBoxW(NULL, L"Usage: Hasher.exe -<mode> <file>", L"Warning", MB_OK);
    }

    LocalFree(argv);

    return 0;
}