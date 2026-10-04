#include <iostream>
#include <string>
#include <cstdint>
#include <format>
#include <fstream>
#include <windows.h>
#include <vector>
#include "ssdeep.h"

#define chunk_size 65536 //размер читаемый чанков из файла


static std::streamsize get_file_size(std::ifstream& file) //выдает размер файла
{
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    return size;
}



static std::vector<uint8_t> get_file_chunk(std::ifstream& file) // чтение файла по чанкам
{
    std::vector<uint8_t> buffer(chunk_size);

    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    std::streamsize bytes_read = file.gcount();

    buffer.resize(static_cast<size_t>(bytes_read)); //меняем размер буффера, если он будет меньше, а он будет меньше в конце чтения

    return buffer;
}



struct HashResult ssdeep(const std::wstring& file_path, struct HashResult& hashes)
{
    std::ifstream file(file_path, std::ios::binary);

    if (!file)
    {
        MessageBoxW(NULL, L"Failed to open target file", L"Error", MB_DEFBUTTON1);
        exit(1);
    }


    std::wstring signature1; //основной хэш, слева от доп. хэша, наполняется значениями сконвертированными через base64 piece_hash
    std::wstring signature2; //доп хэш, справа от основного хэша, наполняется значениями сконвертированными через base64 piece_hash

    constexpr char BASE64[] = //для конвертации piece_hash
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    constexpr uint32_t HASH_INIT = 0x28021967;
    constexpr uint32_t FNV_PRIME = 0x01000193;
    uint32_t block_size = 3;

    uint32_t piece_hash1 = HASH_INIT; //один символ из диапазона хэша, который потом конвертируется в другой символ через base64
    uint32_t piece_hash2 = HASH_INIT; //один символ из диапазона хэша, который потом конвертируется в другой символ через base64, для второй дополнительной сигнатуры

    std::streamsize file_size{ get_file_size(file) };
    if (file_size <= 0) //проверка на пустой файл
    {
        MessageBoxW(NULL, L"File size can't be zero!", L"Error", MB_OK);
        exit(1);
    }

    while (static_cast<std::size_t>(block_size) * 64 < static_cast<size_t>(file_size)) //расчет block_size
    {
        block_size *= 2;
    }

    while (true)
    {
        file.clear(); //очищает флаги
        file.seekg(0, std::ios::beg); //если вдруг надо будет пересчитать сигнатуру заново, когда signature1 меньше 32 символов

        signature1.clear();
        signature2.clear();

        piece_hash1 = HASH_INIT; 
        piece_hash2 = HASH_INIT;

        uint8_t window[7]{}; //rolling hash диапазон

        uint32_t h1 = 0; //хэш сумма, сумма байтов
        uint32_t h2 = 0; //для устранения совпадений хэша, если вдруг диапазон хранит одинаковые байты
        uint32_t h3 = 0; //дополнительная случайность для минимизации совпадений

        int n = 0;

        uint32_t rolling_hash = 0; //нужен для определения границ хэша по которому нужно уже делать piece hash
        char last_char1 = '\0';
        char last_char2 = '\0';


        while (true)
        {

            std::vector<uint8_t> buffer = get_file_chunk(file);

            if (buffer.empty())
            {
                break;
            }

            for (uint8_t c : buffer)
            {
                h2 -= h1;
                h2 += 7 * c;

                h1 -= window[n];
                h1 += c;

                h3 = (h3 << 5) ^ c; 

                window[n] = c;
                n = (n + 1) % 7;

                rolling_hash = h1 + h2 + h3;

                piece_hash1 = (piece_hash1 * FNV_PRIME) ^ c;
                piece_hash2 = (piece_hash2 * FNV_PRIME) ^ c;

                if (rolling_hash % block_size == block_size - 1)
                {
                    last_char1 = BASE64[piece_hash1 % 64];

                    if (signature1.size() < 63) //условия для прекращения вычисления хэша, если сигнатура будет слишком длинной
                    {
                        signature1 += last_char1;
                        piece_hash1 = HASH_INIT;

                        last_char1 = '\0';
                    }
                }

                if (rolling_hash % (block_size * 2) == (block_size * 2) - 1) 
                {
                    last_char2 = BASE64[piece_hash2 % 64];

                    if (signature2.size() < 31) //условия для прекращения вычисления хэша, если сигнатура будет слишком длинной
                    {
                        signature2 += last_char2;
                        piece_hash2 = HASH_INIT;

                        last_char2 = '\0';
                    }
                }
            }
        }

        if (rolling_hash != 0)
        {
            signature1 += BASE64[piece_hash1 % 64];
            signature2 += BASE64[piece_hash2 % 64];
        }
        else
        {
            if (last_char1 != '\0') //условия для прекращения вычисления хэша, если сигнатура будет слишком длинной
            {
                signature1 += last_char1;
            }

            if (last_char2 != '\0') //условия для прекращения вычисления хэша, если сигнатура будет слишком длинной
            {
                signature2 += last_char2;
            }
        }

        if (signature1.size() >= 32 || block_size == 3) //если первая сигнатура signature1 меньше 32, то пропускаем условие и уменьшаем block_size на два чтобы сигнатура была длинее
        {
            break;
        }

        block_size /= 2;
    }

    std::wstring result = std::to_wstring(block_size).append(L":") + signature1.append(L":") + signature2;

    hashes.ssdeep_hash = result;

    return hashes;
}