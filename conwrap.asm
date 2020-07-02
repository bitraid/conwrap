format PE CONSOLE 6.0
entry start

MAX_PATH_SIZE = 4096
PIPE_BUFFER_SIZE = 4096

section '.text' code readable executable

start:
    xor     ebx,ebx
    ; Get the command line and calculate its size
    call    [GetCommandLineW]
    mov     esi,eax
    mov     edi,eax
    xor     ecx,ecx
    xor     eax,eax
    not     ecx
    cld
    repnz scasw
    not     ecx
    mov     edi,ecx
    ; Allocate heap memory and setup pointers
    shl     ecx,1
    add     ecx,MAX_PATH_SIZE+2*PIPE_BUFFER_SIZE
    push    ecx                 ; dwBytes (HeapAlloc)
    push    ebx                 ; dwFlags (HeapAlloc)
    call    [GetProcessHeap]
    push    eax                 ; hHeap
    call    [HeapAlloc]
    test    eax,eax
    jz      .exit
    mov     [stdout.lpBuffer],eax
    add     eax,PIPE_BUFFER_SIZE
    mov     [stderr.lpBuffer],eax
    add     eax,PIPE_BUFFER_SIZE
    mov     [exe.lpFullPath],eax
    add     eax,MAX_PATH_SIZE
    mov     [exe.lpCommandLine],eax
    ; Copy command line to heap memory so it can be used with CreateProcess
    mov     ecx,edi
    mov     edi,eax
    rep movsw
    ; Set the target executable path
    mov     edi,[exe.lpFullPath]
    push    MAX_PATH_SIZE       ; nSize
    push    edi                 ; lpFilename
    push    ebx                 ; hModule
    call    [GetModuleFileNameW]
    shl     eax,1
    cmp     dword [edi+eax-8],0063002Eh
    jne     .exit
    cmp     dword [edi+eax-4],006D006fh
    jne     .exit
    mov     dword [edi+eax-8],0065002Eh
    mov     dword [edi+eax-4],00650078h
    ; Create inheritable anonymous pipes for stdout and stderr
    mov     edi,[CreatePipe]
    mov     esi,[CloseHandle]
    push    1000h               ; nSize
    push    sattr               ; lpPipeAttributes
    push    stderr.hWritePipe   ; hWritePipe
    push    stderr.hReadPipe    ; hReadPipe
    call    edi
    test    eax,eax
    jz      .exit
    push    1000h               ; nSize
    push    sattr               ; lpPipeAttributes
    push    stdout.hWritePipe   ; hWritePipe
    push    stdout.hReadPipe    ; hReadPipe
    call    edi
    test    eax,eax
    jne     @f
    push    [stderr.hReadPipe]
    push    [stderr.hWritePipe]
    call    esi
    call    esi
    jmp     .exit
@@: ; Setup STARTUPINFO structure
    mov     edi,[GetStdHandle]
    push    sinfo               ; lpStartupInfo
    call    [GetStartupInfoW]
    push    -12                 ; nStdHandle
    call    edi
    mov     [stderr.hStdDevice],eax
    push    -11                 ; nStdHandle
    call    edi
    mov     [stdout.hStdDevice],eax
    push    -10                 ; nStdHandle
    call    edi
    mov     ecx,[stdout.hWritePipe]
    mov     edx,[stderr.hWritePipe]
    mov     [sinfo.lpDesktop],ebx
    mov     [sinfo.lpTitle],ebx
    mov     [sinfo.dwFlags],0100h
    mov     [sinfo.hStdInput],eax
    mov     [sinfo.hStdOutput],ecx
    mov     [sinfo.hStdError],edx
    ; Add CTRL-C handler
    push    1                   ; bAdd
    push    control_handler     ; HandlerRoutine
    call    [SetConsoleCtrlHandler]
    ; Create the target process with inherited handles and unicode environment
    push    pinfo               ; lpProcessInformation
    push    sinfo               ; lpStartupInfo
    push    ebx                 ; lpCurrentDirectory
    push    ebx                 ; lpEnvironment
    push    0400h               ; dwCreationFlags
    push    1                   ; bInheritHandles
    push    sattr               ; lpThreadAttributes
    push    sattr               ; lpProcessAttributes
    push    [exe.lpCommandLine] ; lpCommandLine
    push    [exe.lpFullPath]    ; lpApplicationName
    call    [CreateProcessW]
    mov     edi,eax
    ; Close the handles to the write end of the pipes
    push    [stderr.hWritePipe]
    push    [stdout.hWritePipe]
    call    esi
    call    esi
    test    edi,edi
    jz      .exec_fail
    ; Create and start threads for reading the pipes and writing to stdout/stderr
    lea     edi,[output_pipe]
    push    ebx                 ; lpThreadId
    push    ebx                 ; dwCreationFlags
    push    stderr              ; lpParameter
    push    edi                 ; lpStartAddress
    push    ebx                 ; dwStackSize
    push    ebx                 ; lpThreadAttributes
    call    [CreateThread]
    mov     [threads.hStdErrThread],eax
    push    ebx                 ; lpThreadId
    push    ebx                 ; dwCreationFlags
    push    stdout              ; lpParameter
    push    edi                 ; lpStartAddress
    push    ebx                 ; dwStackSize
    push    ebx                 ; lpThreadAttributes
    call    [CreateThread]
    mov     [threads.hStdOutThread],eax
    ; Wait for threads to finish
    push    -1                  ; dwMilliseconds
    push    1                   ; bWaitAll
    push    threads             ; *lpHandles
    push    2                   ; nCount
    call    [WaitForMultipleObjects]
    ; Close thread handles
    push    [threads.hStdErrThread]
    push    [threads.hStdOutThread]
    call    esi
    call    esi
    jmp     .exec_finish
.exec_fail:
    inc     ebx
.exec_finish:
    ; Remove CTRL-C handler
    push    0                   ; bAdd
    push    control_handler     ; HandlerRoutine
    call    [SetConsoleCtrlHandler]
    ; Close the handles to the read end of the pipes
    push    [stderr.hReadPipe]
    push    [stdout.hReadPipe]
    call    esi
    call    esi
    test    ebx,ebx
    jnz     @f
    ; Wait for target process to exit
    push    -1                  ; dwMilliseconds
    push    [pinfo.hProcess]    ; hHandle
    call    [WaitForSingleObject]
    ; Get the exit code of the target process
    push    exe.uExitCode       ; lpExitCode
    push    [pinfo.hProcess]    ; hProcess
    call    [GetExitCodeProcess]
@@: ; Close remaining handles
    push    [pinfo.hThread]
    push    [pinfo.hProcess]
    push    [sinfo.hStdInput]
    push    [stdout.hStdDevice]
    push    [stderr.hStdDevice]
    call    esi
    call    esi
    call    esi
    call    esi
    call    esi
.exit:
    push    [exe.uExitCode]
    call    [ExitProcess]

control_handler:
    mov     eax,[pinfo.hProcess]
    test    eax,eax
    jz      @f
    push    0                   ; dwMilliseconds
    push    eax                 ; hHandle
    call    [WaitForSingleObject]
    cmp     eax,102h
    jnz     @f
    push    2                   ; uExitCode
    push    [pinfo.hProcess]    ; hProcess
    call    [TerminateProcess]
    xor     eax,eax
    inc     eax
    ret     4
@@:
    xor     eax,eax
    ret     4

output_pipe:
    push    ebp
    mov     ebp,esp
    sub     esp,8
    mov     eax,[ebp+8]
    mov     edi,[eax]
    mov     esi,[eax+4]
    mov     ebx,[eax+12]
.read_pipe:
    lea     ecx,[ebp-4]
    push    0                   ; lpOverlapped
    push    ecx                 ; lpNumberOfBytesRead
    push    PIPE_BUFFER_SIZE    ; nNumberOfBytesToRead
    push    ebx                 ; lpBuffer
    push    esi                 ; hFile
    call    [ReadFile]
    test    eax,eax
    jz      .return
    mov     eax,[ebp-4]
    test    eax,eax
    jz      .check_state
.write_output:
    lea     ecx,[ebp-8]
    push    0                   ; lpOverlapped
    push    ecx                 ; lpNumberOfBytesWritten
    push    eax                 ; nNumberOfBytesToWrite
    push    ebx                 ; lpBuffer
    push    edi                 ; hFile
    call    [WriteFile]
.check_state:
    push    0                   ; dwMilliseconds
    push    [pinfo.hProcess]    ; hHandle
    call    [WaitForSingleObject]
    cmp     eax,0102h
    jz      .read_pipe
.return:
    mov     esp,ebp
    pop     ebp
    ret     4

section '.data' data readable writeable

struc STARTUPINFO {
    .cb              dd ?
    .lpReserved      dd ?
    .lpDesktop       dd ?
    .lpTitle         dd ?
    .dwX             dd ?
    .dwY             dd ?
    .dwXSize         dd ?
    .dwYSize         dd ?
    .dwXCountChars   dd ?
    .dwYCountChars   dd ?
    .dwFillAttribute dd ?
    .dwFlags         dd ?
    .wShowWindow     dw ?
    .cbReserved2     dw ?
    .lpReserved2     dd ?
    .hStdInput       dd ?
    .hStdOutput      dd ?
    .hStdError       dd ?
}

struc PROCESS_INFORMATION {
    .hProcess    dd ?
    .hThread     dd ?
    .dwProcessId dd ?
    .dwThreadId  dd ?
}

struc SECURITY_ATTRIBUTES {
    .nLength              dd 12
    .lpSecurityDescriptor dd 0
    .bInheritHandle       dd 1
}

struc PIPE {
    .hStdDevice dd ?
    .hReadPipe  dd ?
    .hWritePipe dd ?
    .lpBuffer   dd ?
}

struc THREAD_HANDLES {
    .hStdOutThread dd ?
    .hStdErrThread dd ?
}

struc TARGET_EXE {
    .lpFullPath    dd ?
    .lpCommandLine dd ?
    .uExitCode     dd 1
}

    sinfo STARTUPINFO
    pinfo PROCESS_INFORMATION
    sattr SECURITY_ATTRIBUTES

    stdout PIPE
    stderr PIPE

    threads THREAD_HANDLES

    exe TARGET_EXE

section '.idata' import data readable writeable
    dd 0,0,0,RVA kernel_name,RVA kernel_table
    dd 0,0,0,0,0

kernel_table:
    CloseHandle            dd RVA _CloseHandle
    CreatePipe             dd RVA _CreatePipe
    CreateProcessW         dd RVA _CreateProcessW
    CreateThread           dd RVA _CreateThread
    ExitProcess            dd RVA _ExitProcess
    GetCommandLineW        dd RVA _GetCommandLineW
    GetExitCodeProcess     dd RVA _GetExitCodeProcess
    GetModuleFileNameW     dd RVA _GetModuleFileNameW
    GetProcessHeap         dd RVA _GetProcessHeap
    GetStartupInfoW        dd RVA _GetStartupInfoW
    GetStdHandle           dd RVA _GetStdHandle
    HeapAlloc              dd RVA _HeapAlloc
    ReadFile               dd RVA _ReadFile
    SetConsoleCtrlHandler  dd RVA _SetConsoleCtrlHandler
    TerminateProcess       dd RVA _TerminateProcess
    WaitForMultipleObjects dd RVA _WaitForMultipleObjects
    WaitForSingleObject    dd RVA _WaitForSingleObject
    WriteFile              dd RVA _WriteFile
    dd 0

    kernel_name db 'KERNEL32.DLL',0

    _CloseHandle dw 0
    db 'CloseHandle',0

    _CreatePipe dw 0
    db 'CreatePipe',0

    _CreateProcessW dw 0
    db 'CreateProcessW',0

    _CreateThread dw 0
    db 'CreateThread',0

    _ExitProcess dw 0
    db 'ExitProcess',0

    _GetCommandLineW dw 0
    db 'GetCommandLineW',0

    _GetExitCodeProcess dw 0
    db 'GetExitCodeProcess',0

    _GetModuleFileNameW dw 0
    db 'GetModuleFileNameW',0

    _GetProcessHeap dw 0
    db 'GetProcessHeap',0

    _GetStartupInfoW dw 0
    db 'GetStartupInfoW',0

    _GetStdHandle dw 0
    db 'GetStdHandle',0

    _HeapAlloc dw 0
    db 'HeapAlloc',0

    _ReadFile dw 0
    db 'ReadFile',0

    _SetConsoleCtrlHandler dw 0
    db 'SetConsoleCtrlHandler',0

    _TerminateProcess dw 0
    db 'TerminateProcess',0

    _WaitForMultipleObjects dw 0
    db 'WaitForMultipleObjects',0

    _WaitForSingleObject dw 0
    db 'WaitForSingleObject',0

    _WriteFile dw 0
    db 'WriteFile',0
