#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include "Hasher.h"

struct HashResult ssdeep(const std::wstring& file_path, struct HashResult& hashes);
static std::vector<uint8_t> get_file_chunk(std::ifstream& file);
static std::streamsize get_file_size(std::ifstream& file);