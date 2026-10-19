/*
   Ghost Sandbox — Named Pipe Client
   Ring-buffer backed async event sender for the injected shim.
   (c) 2026 Ghost Project
*/
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "trace_format.h"

/* ─── Ring Buffer ────────────────────────────────────────── */
#define RING_BUFFER_SIZE (256 * 1024)  // 256KB ring buffer

class RingBuffer {
    BYTE buffer[RING_BUFFER_SIZE];
    volatile LONG writePos;
    volatile LONG readPos;
    CRITICAL_SECTION lock;
    
public:
    void Init() {
        writePos = 0;
        readPos = 0;
        InitializeCriticalSection(&lock);
    }
    
    void Destroy() {
        DeleteCriticalSection(&lock);
    }
    
    // Write data to ring buffer (non-blocking, drops data if full)
    BOOL Write(const void* data, DWORD size) {
        EnterCriticalSection(&lock);
        
        LONG wp = writePos;
        LONG rp = readPos;
        LONG available = (rp > wp) ? (rp - wp - 1) : (RING_BUFFER_SIZE - wp + rp - 1);
        
        if ((LONG)size > available) {
            LeaveCriticalSection(&lock);
            return FALSE;  // Drop event — buffer full
        }
        
        // Write with wrap-around
        LONG firstPart = min((LONG)size, RING_BUFFER_SIZE - wp);
        memcpy(buffer + wp, data, firstPart);
        if ((LONG)size > firstPart) {
            memcpy(buffer, (BYTE*)data + firstPart, size - firstPart);
        }
        
        writePos = (wp + size) % RING_BUFFER_SIZE;
        LeaveCriticalSection(&lock);
        return TRUE;
    }
    
    // Read data from ring buffer
    DWORD Read(void* dest, DWORD maxSize) {
        EnterCriticalSection(&lock);
        
        LONG wp = writePos;
        LONG rp = readPos;
        LONG dataAvailable = (wp >= rp) ? (wp - rp) : (RING_BUFFER_SIZE - rp + wp);
        
        DWORD toRead = min((DWORD)dataAvailable, maxSize);
        if (toRead == 0) {
            LeaveCriticalSection(&lock);
            return 0;
        }
        
        LONG firstPart = min((LONG)toRead, RING_BUFFER_SIZE - rp);
        memcpy(dest, buffer + rp, firstPart);
        if ((LONG)toRead > firstPart) {
            memcpy((BYTE*)dest + firstPart, buffer, toRead - firstPart);
        }
        
        readPos = (rp + toRead) % RING_BUFFER_SIZE;
        LeaveCriticalSection(&lock);
        return toRead;
    }
    
    BOOL HasData() {
        return writePos != readPos;
    }
};

/* ─── Pipe Client ────────────────────────────────────────── */

// Callback for processing commands from the controller
typedef void (*CommandCallback)(const CommandHeader* cmd);

class PipeClient {
    HANDLE hPipe;
    HANDLE hSendThread;
    HANDLE hRecvThread;
    HANDLE hStopEvent;
    RingBuffer sendBuffer;
    CommandCallback cmdCallback;
    CRITICAL_SECTION sendLock;
    BOOL connected;
    /* Command reassembly: a byte-mode ReadFile may return a partial command or
       several coalesced commands — buffer, then dispatch every complete one. */
    BYTE recvPending[16384];
    DWORD recvPendingLen;
    
    static DWORD WINAPI SendThreadProc(LPVOID param) {
        PipeClient* self = (PipeClient*)param;
        BYTE tempBuf[4096];
        ShimLog("[pipe] send thread started");
        
        while (WaitForSingleObject(self->hStopEvent, 10) == WAIT_TIMEOUT) {
            if (!self->connected || !self->sendBuffer.HasData()) continue;
            
            DWORD bytesRead = self->sendBuffer.Read(tempBuf, sizeof(tempBuf));
            if (bytesRead > 0) {
                DWORD bytesWritten = 0;
                if (!WriteFile(self->hPipe, tempBuf, bytesRead, &bytesWritten, NULL)) {
                    ShimLog("[pipe] WriteFile failed err=%lu", GetLastError());
                    self->connected = FALSE;
                }
            }
        }
        ShimLog("[pipe] send thread exiting");
        return 0;
    }
    
    static DWORD WINAPI RecvThreadProc(LPVOID param) {
        PipeClient* self = (PipeClient*)param;
        ShimLog("[pipe] recv thread started");
        
        while (WaitForSingleObject(self->hStopEvent, 0) == WAIT_TIMEOUT) {
            if (!self->connected) {
                Sleep(100);
                continue;
            }
            
            // IMPORTANT: do not park a blocking ReadFile on an idle pipe.
            // A pending synchronous read blocks writes on the same handle,
            // which would deadlock the send thread inside WriteFile.
            // Poll instead; when bytes are queued, ReadFile returns at once.
            DWORD avail = 0;
            if (!PeekNamedPipe(self->hPipe, NULL, 0, NULL, &avail, NULL)) {
                DWORD err = GetLastError();
                ShimLog("[pipe] PeekNamedPipe failed err=%lu", err);
                if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                    self->connected = FALSE;
                }
                Sleep(100);
                continue;
            }
            if (avail == 0) {
                Sleep(20);
                continue;
            }
            
            DWORD space = (DWORD)sizeof(self->recvPending) - self->recvPendingLen;
            if (space == 0) {
                /* A single command larger than our buffer can never be
                   processed — drop it and resynchronise. */
                ShimLog("[pipe] recv buffer full (%lu bytes) — dropping buffer", self->recvPendingLen);
                self->recvPendingLen = 0;
                space = (DWORD)sizeof(self->recvPending);
                avail = 0;   /* re-peek */
                continue;
            }
            if (avail > space) avail = space;
            
            DWORD bytesRead = 0;
            if (ReadFile(self->hPipe, self->recvPending + self->recvPendingLen, avail,
                         &bytesRead, NULL) && bytesRead > 0) {
                self->recvPendingLen += bytesRead;
                
                // Dispatch every complete command in the buffer (a write may
                // carry several commands, or a command may span reads).
                DWORD off = 0;
                while (self->recvPendingLen - off >= sizeof(CommandHeader)) {
                    const CommandHeader* cmd =
                        (const CommandHeader*)(self->recvPending + off);
                    if (cmd->size < sizeof(CommandHeader) ||
                        cmd->size > self->recvPendingLen - off) {
                        break;   // wait for the rest of the command
                    }
                    if (self->cmdCallback) self->cmdCallback(cmd);
                    off += cmd->size;
                }
                if (off > 0) {
                    memmove(self->recvPending, self->recvPending + off,
                            self->recvPendingLen - off);
                    self->recvPendingLen -= off;
                }
            } else {
                DWORD err = GetLastError();
                ShimLog("[pipe] ReadFile ended err=%lu", err);
                if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                    self->connected = FALSE;
                }
                Sleep(50);
            }
        }
        ShimLog("[pipe] recv thread exiting");
        return 0;
    }
    
public:
    void Init(CommandCallback callback) {
        hPipe = INVALID_HANDLE_VALUE;
        hSendThread = NULL;
        hRecvThread = NULL;
        cmdCallback = callback;
        connected = FALSE;
        recvPendingLen = 0;
        sendBuffer.Init();
        InitializeCriticalSection(&sendLock);
        hStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    }
    
    BOOL IsConnected() { return connected; }
    
    void Destroy() {
        SetEvent(hStopEvent);
        
        if (hSendThread) { WaitForSingleObject(hSendThread, 2000); CloseHandle(hSendThread); }
        if (hRecvThread) { WaitForSingleObject(hRecvThread, 2000); CloseHandle(hRecvThread); }
        if (hPipe != INVALID_HANDLE_VALUE) { CloseHandle(hPipe); }
        
        CloseHandle(hStopEvent);
        sendBuffer.Destroy();
        DeleteCriticalSection(&sendLock);
    }
    
    BOOL Connect() {
        // Try to connect to the controller's named pipe
        hPipe = CreateFileA(
            GHOST_SANDBOX_PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );
        
        if (hPipe == INVALID_HANDLE_VALUE) {
            // The controller (GUI) may still be starting up — keep retrying in
            // the background instead of losing the session permanently.
            ShimLog("[pipe] CreateFileA failed err=%lu (retrying in background)",
                    GetLastError());
            CreateThread(NULL, 0, ConnectThreadProc, this, 0, NULL);
            return FALSE;
        }
        
        FinishConnect();
        return TRUE;
    }
    
    // Complete a successful pipe connection: switch to byte mode and start
    // the send/receive threads.
    void FinishConnect() {
        // Set pipe to message mode
        DWORD mode = PIPE_READMODE_BYTE;
        if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
            ShimLog("[pipe] SetNamedPipeHandleState failed err=%lu", GetLastError());
        }
        
        recvPendingLen = 0;
        connected = TRUE;
        
        // Start send and receive threads
        hSendThread = CreateThread(NULL, 0, SendThreadProc, this, 0, NULL);
        hRecvThread = CreateThread(NULL, 0, RecvThreadProc, this, 0, NULL);
        ShimLog("[pipe] connected (h=%p sendT=%p recvT=%p)",
                (void*)hPipe, (void*)hSendThread, (void*)hRecvThread);
    }
    
    // Background connector: retries until the controller's pipe appears
    // (up to 60 s), so injecting into a target before/while the GUI starts
    // still yields a live session.
    static DWORD WINAPI ConnectThreadProc(LPVOID param) {
        PipeClient* self = (PipeClient*)param;
        for (int attempt = 1; attempt <= 120; attempt++) {
            if (WaitForSingleObject(self->hStopEvent, 500) != WAIT_TIMEOUT) {
                return 0;  // shutting down
            }
            HANDLE h = CreateFileA(
                GHOST_SANDBOX_PIPE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (h != INVALID_HANDLE_VALUE) {
                self->hPipe = h;
                self->FinishConnect();
                ShimLog("[pipe] late connect succeeded after %d ms", attempt * 500);
                return 0;
            }
        }
        ShimLog("[pipe] connect retries exhausted (controller not running)");
        return 0;
    }
    
    // Send an event to the controller (non-blocking)
    BOOL SendEvent(const void* event, DWORD size) {
        if (!connected) return FALSE;
        
        EnterCriticalSection(&sendLock);
        BOOL result = sendBuffer.Write(event, size);
        LeaveCriticalSection(&sendLock);
        if (!result) {
            static int drops = 0;
            static int droppedBytes = 0;
            droppedBytes += (int)size;
            if (drops++ < 20) {
                ShimLog("[pipe] SendEvent dropped (ring full) size=%lu totalDropped=%d",
                        size, droppedBytes);
            }
        }
        return result;
    }
    
    // Send a trace event helper
    void SendTrace(const char* funcName, const char* moduleName,
                   const char* params, const char* retVal,
                   ULONGLONG durationUs, BOOL spoofed,
                   ULONGLONG rax, ULONGLONG rcx, ULONGLONG rdx,
                   ULONGLONG r8, ULONGLONG r9, ULONGLONG rsp, ULONGLONG rip) {
        TraceEventTrace evt = {};
        evt.header.type = spoofed ? EVT_SPOOF : EVT_TRACE;
        evt.header.size = sizeof(evt);
        QueryPerformanceCounter(&evt.header.timestamp);
        evt.header.threadId = GetCurrentThreadId();
        
        strncpy_s(evt.functionName, funcName, _TRUNCATE);
        strncpy_s(evt.moduleName, moduleName, _TRUNCATE);
        strncpy_s(evt.params, params, _TRUNCATE);
        strncpy_s(evt.returnValue, retVal, _TRUNCATE);
        evt.durationUs = durationUs;
        evt.spoofed = spoofed ? 1 : 0;
        evt.rax = rax; evt.rcx = rcx; evt.rdx = rdx;
        evt.r8 = r8; evt.r9 = r9; evt.rsp = rsp; evt.rip = rip;
        
        SendEvent(&evt, sizeof(evt));
    }
    
    // Send a DLL load notification
    void SendDllLoad(const char* name, ULONGLONG base, ULONGLONG size) {
        TraceEventDllLoad evt = {};
        evt.header.type = EVT_DLL_LOAD;
        evt.header.size = sizeof(evt);
        QueryPerformanceCounter(&evt.header.timestamp);
        evt.header.threadId = GetCurrentThreadId();
        strncpy_s(evt.dllName, name, _TRUNCATE);
        evt.baseAddress = base;
        evt.size = size;
        SendEvent(&evt, sizeof(evt));
    }
    
    BOOL IsConnected() const { return connected; }
};
