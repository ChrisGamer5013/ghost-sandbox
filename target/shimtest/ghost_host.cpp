/*
   ghost_host.exe — minimal DLL host for Ghost Sandbox.

   The sandbox can instrument EXEs directly, but a DLL only runs code once a
   host loads it. This host:

       ghost_host.exe <dll-path> [export-name] [--seconds N] [--args "..."]

   - loads the DLL with LoadLibraryW (DllMain runs — policy is already armed
     in the process before that happens),
   - optionally resolves and calls one export (cdecl, no arguments),
   - stays alive for N seconds (default 120) so the shim can stream events,
   - unloads on exit (skipped when --seconds 0 = wait for Ctrl+C).

   If the DLL cannot be found through the normal search path it is loaded by
   absolute path, so relative/absolute CLI arguments both work.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_seconds(int argc, wchar_t** argv, int* has_args) {
    int seconds = 120;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--seconds") == 0 && i + 1 < argc) {
            seconds = _wtoi(argv[i + 1]);
            if (seconds < 0) seconds = 0;
        } else if (wcscmp(argv[i], L"--args") == 0) {
            *has_args = 1;
        }
    }
    return seconds;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr,
                 L"usage: ghost_host.exe <dll-path> [export] [--seconds N] [--args \"...\"]\n");
        return 2;
    }

    const wchar_t* dll = argv[1];
    const wchar_t* export_name = NULL;
    int has_args = 0;
    int seconds = parse_seconds(argc, argv, &has_args);

    for (int i = 2; i < argc; i++) {
        if (argv[i][0] == L'-') {
            // skip option values
            if ((wcscmp(argv[i], L"--seconds") == 0 || wcscmp(argv[i], L"--args") == 0) &&
                i + 1 < argc) {
                i++;
            }
            continue;
        }
        if (!export_name) export_name = argv[i];
    }

    // Get the full path so LoadLibrary does not depend on the search order.
    wchar_t full[MAX_PATH * 4];
    DWORD n = GetFullPathNameW(dll, MAX_PATH * 4, full, NULL);
    if (n == 0 || n >= MAX_PATH * 4) {
        wcscpy_s(full, MAX_PATH * 4, dll);
    }

    fwprintf(stderr, L"[ghost_host] loading %ls\n", full);
    HMODULE mod = LoadLibraryW(full);
    if (!mod) {
        DWORD err = GetLastError();
        fwprintf(stderr, L"[ghost_host] LoadLibraryW failed: %lu (0x%08lX)\n", err, err);
        return 3;
    }
    fwprintf(stderr, L"[ghost_host] %ls loaded at %p\n", full, (void*)mod);

    if (has_args) {
        // The target DLL re-parses its own command line; nothing to do here —
        // we only keep the arguments in our own command line (visible to the
        // target via GetCommandLineW).
        fwprintf(stderr, L"[ghost_host] passing command line through to the DLL\n");
    }

    if (export_name && export_name[0]) {
        // Support "module.ExportName" and plain "ExportName". GetProcAddress
        // is ANSI-only; export names are ASCII in practice.
        const wchar_t* dot = wcsrchr(export_name, L'.');
        const wchar_t* wproc = dot ? dot + 1 : export_name;
        char proc[256];
        if (WideCharToMultiByte(CP_ACP, 0, wproc, -1, proc, sizeof(proc), NULL, NULL) == 0) {
            fwprintf(stderr, L"[ghost_host] export name not convertible\n");
            FreeLibrary(mod);
            return 4;
        }
        FARPROC fn = GetProcAddress(mod, proc);
        if (fn) {
            fwprintf(stderr, L"[ghost_host] calling export %hs at %p\n", proc, (void*)fn);
            typedef int(__cdecl * ExportFn)(void);
            int rc = ((ExportFn)fn)();
            fwprintf(stderr, L"[ghost_host] export returned %d\n", rc);
        } else {
            fwprintf(stderr, L"[ghost_host] export '%hs' not found (GetProcAddress: %lu)\n",
                     proc, GetLastError());
        }
    }

    if (seconds > 0) {
        fwprintf(stderr, L"[ghost_host] waiting %d s…\n", seconds);
        Sleep((DWORD)seconds * 1000);
    } else {
        fwprintf(stderr, L"[ghost_host] waiting for Ctrl+C…\n");
        // Sleep in slices so the process stays responsive to console events.
        for (;;) Sleep(1000);
    }

    // Let other threads (and the shim) finish flushing before we unload.
    Sleep(250);
    FreeLibrary(mod);
    fwprintf(stderr, L"[ghost_host] done\n");
    return 0;
}
