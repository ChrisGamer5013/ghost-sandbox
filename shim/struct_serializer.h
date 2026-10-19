/*
   Ghost Sandbox — Struct Serializer
   Serialize Windows structures into human-readable strings for trace events.
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

/* ─── Parameter Formatting Helpers ───────────────────────── */

static void FormatWideString(char* dest, size_t destSize, const wchar_t* src) {
    if (!src) {
        strncpy_s(dest, destSize, "(null)", _TRUNCATE);
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dest, (int)destSize, NULL, NULL);
}

static void FormatPointer(char* dest, size_t destSize, const void* ptr) {
    if (!ptr) {
        strncpy_s(dest, destSize, "NULL", _TRUNCATE);
    } else {
        snprintf(dest, destSize, "0x%p", ptr);
    }
}

static void FormatDword(char* dest, size_t destSize, DWORD val) {
    snprintf(dest, destSize, "0x%08X (%u)", val, val);
}

static void FormatHResult(char* dest, size_t destSize, HRESULT hr) {
    switch (hr) {
        case S_OK: strncpy_s(dest, destSize, "S_OK", _TRUNCATE); break;
        case E_FAIL: strncpy_s(dest, destSize, "E_FAIL", _TRUNCATE); break;
        case E_INVALIDARG: strncpy_s(dest, destSize, "E_INVALIDARG", _TRUNCATE); break;
        case E_OUTOFMEMORY: strncpy_s(dest, destSize, "E_OUTOFMEMORY", _TRUNCATE); break;
        default: snprintf(dest, destSize, "0x%08X", hr); break;
    }
}

static void FormatBool(char* dest, size_t destSize, BOOL val) {
    strncpy_s(dest, destSize, val ? "TRUE" : "FALSE", _TRUNCATE);
}

static void FormatLastError(char* dest, size_t destSize) {
    DWORD err = GetLastError();
    snprintf(dest, destSize, "err=%u", err);
}

/* ─── Timing Helper ──────────────────────────────────────── */

static ULONGLONG MicrosecondsSince(LARGE_INTEGER start) {
    LARGE_INTEGER end, freq;
    QueryPerformanceCounter(&end);
    QueryPerformanceFrequency(&freq);
    return (ULONGLONG)((end.QuadPart - start.QuadPart) * 1000000ULL / freq.QuadPart);
}
