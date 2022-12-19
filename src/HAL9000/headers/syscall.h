#pragma once

#include "process_internal.h"
#include "syscall_defs.h"
#include "thread_internal.h"
#include "filesystem.h"


typedef struct _PROCESS_HANDLE {

    PPROCESS             Process;

    UM_HANDLE            Handle;

    LIST_ENTRY           ProcessHandleList;

} PROCESS_HANDLE, * PPROCESS_HANDLE;


struct _PROCESS_HANDLE_LIST {

    LIST_ENTRY ProcessHandleListHead;
};

typedef struct _FILE_HANDLE {

    PFILE_OBJECT          File;

    UM_HANDLE            Handle;

    LIST_ENTRY           FileHandleList;

} FILE_HANDLE, * PFILE_HANDLE;


struct _FILE_HANDLE_LIST {

    LIST_ENTRY FileHandleListHead;
};

typedef struct _THREAD_HANDLE {

    struct _THREAD*      Thread;

    UM_HANDLE            Handle;

    LIST_ENTRY           ThreadHandleList;

} THREAD_HANDLE, * PTHREAD_HANDLE;


struct _THREAD_HANDLE_LIST {

    LIST_ENTRY ThreadHandleList;

};

void
SyscallPreinitSystem(
    void
);

STATUS
SyscallInitSystem(
    void
);

STATUS
SyscallUninitSystem(
    void
);

void
SyscallCpuInit(
    void
);

STATUS
FindProcessByUM_HANDLE(
    IN UM_HANDLE ProcessHandle,
    OUT PPROCESS* Process
);

STATUS
CloseAndDeleteProcessByUM_HANDLE(
    IN UM_HANDLE        ProcessHandle
);

STATUS
FindFileByUM_HANDLE(
    IN UM_HANDLE                 FileHandle,
    OUT PFILE_OBJECT* pFile
);

STATUS
CloseAndDeleteFileByUM_HANDLE(
    IN UM_HANDLE                 FileHandle
);

STATUS
FindThreadByUM_HANDLE(
    IN UM_HANDLE ThreadHandle,
    OUT PTHREAD* pThread
);

STATUS
CloseAndDeleteThreadByUM_HANDLE(
    IN UM_HANDLE        ThreadHandle
);