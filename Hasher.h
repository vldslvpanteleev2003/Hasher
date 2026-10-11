#pragma once
#include <string>
#include <vector>
#include <cstdint>

static void CopyCopyToClipboard(const std::wstring&);
static void OpenVirusTotal(const std::wstring&);
static void CheckSignature(const wchar_t*);
static void calculate_hash(const wchar_t*, std::vector<std::wstring> algorithms);
LRESULT CALLBACK Wndproc(HWND, UINT, WPARAM, LPARAM);
static int ShowHash(HINSTANCE, int, std::wstring sha256_hash, std::wstring ssdepp_hash);
static std::vector<uint8_t> get_file_chunk(std::ifstream& file);
static std::streamsize get_file_size(std::ifstream& file);
void read_chunks(std::wstring filepath, std::vector<struct HashContext>& Contexts);