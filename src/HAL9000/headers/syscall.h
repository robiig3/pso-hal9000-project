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

    FILE_OBJECT          File;

    UM_HANDLE            Handle;

    LIST_ENTRY           FileHandleList;

} FILE_HANDLE, * FILE_HANDLE;


struct _FILE_HANDLE_LIST {

    LIST_ENTRY FileHandleListHead;
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
