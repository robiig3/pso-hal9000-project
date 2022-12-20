#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "io.h"
#include "iomu.h"
#include "cl_string.h"
#include "process.h"
//#include "stdlib.h"
//#include "stdio.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION
#define TAG_CREATE_PROCESS 'PCT'
#define TAG_CREATE_THREAD 'TCR'
#define TAG_CREATE_FILE 'FCR'

UM_HANDLE HANDLE_ID_INCREMENT = 2;

static struct _PROCESS_HANDLE_LIST m_processHandleList;
static struct _FILE_HANDLE_LIST m_fileHandleList;
static struct _THREAD_HANDLE_LIST m_threadHandleList;

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE* CompleteProcessorState
)
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
            // STUDENT TODO: implement the rest of the syscalls
                    //PROCESSES
        case SyscallIdProcessExit:
            status = SyscallProcessExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate((char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1], (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3], (UM_HANDLE*)pSyscallParameters[4]);
            break;
        case SyscallIdProcessGetPid:
            status = SyscallProcessGetPid((UM_HANDLE)pSyscallParameters[0], (PID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessWaitForTermination:
            status = SyscallProcessWaitForTermination((UM_HANDLE)pSyscallParameters[0], (STATUS*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessCloseHandle:
            status = SyscallProcessCloseHandle((UM_HANDLE)*pSyscallParameters);
            break;
        case SyscallIdFileCreate:
            status = SyscallFileCreate((char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1], (BOOLEAN)pSyscallParameters[2],
                (BOOLEAN)pSyscallParameters[3], (UM_HANDLE*)pSyscallParameters[4]);
            break;
        case SyscallIdFileClose:
            status = SyscallFileClose((UM_HANDLE)*pSyscallParameters);
            break;
        case SyscallIdFileRead:
            status = SyscallFileRead((UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1], (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]);
            break;
        //THREADS
        case SyscallIdThreadExit:
            status = SyscallThreadExit((STATUS)*pSyscallParameters);
            break;
        case SyscallIdThreadCreate:
            status = SyscallThreadCreate((PFUNC_ThreadStart)pSyscallParameters[0], 
                (PVOID)pSyscallParameters[1], (UM_HANDLE*)pSyscallParameters[2]);
            break;
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0], (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdThreadWaitForTermination:
            status = SyscallThreadWaitForTermination((UM_HANDLE)pSyscallParameters[0], (STATUS*)pSyscallParameters[1]);
            break;
        case SyscallIdThreadCloseHandle:
            status = SyscallThreadCloseHandle((UM_HANDLE)pSyscallParameters);
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
)
{
    // initializam listele de ProcessHandle, FileHandle si ThreadHandle
    InitializeListHead(&m_processHandleList.ProcessHandleListHead);
    InitializeListHead(&m_fileHandleList.FileHandleListHead);
    InitializeListHead(&m_threadHandleList.ThreadHandleList);
}

STATUS
SyscallInitSystem(
    void
)
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
)
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
)
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD)SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD)SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
// PROCESSES
//SyscallIdProcessExit
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    //UNREFERENCED_PARAMETER(ExitStatus);
    PPROCESS pProcess = GetCurrentProcess();

    if (pProcess == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    pProcess->TerminationStatus = ExitStatus;
    ProcessTerminate(pProcess);
    
    return STATUS_SUCCESS;
}

// SyscallIdProcessCreate
STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{
    PPROCESS pProcess;
    STATUS Status;
    const char* SystemDrive;
    char absolutePath[MAX_PATH];

    if (ProcessPath == NULL || ProcessHandle == NULL || PathLength <= 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (ArgLength != 0) {
        if (Arguments == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
    }

    if (MmuIsBufferValid((char*)ProcessPath, sizeof(char) * PathLength, PAGE_RIGHTS_READ, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    if (MmuIsBufferValid((UM_HANDLE*)ProcessHandle, sizeof(UM_HANDLE), PAGE_RIGHTS_READWRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    if (ArgLength != 0) {
        if (Arguments == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        if (MmuIsBufferValid((char*)Arguments, sizeof(char) * ArgLength, PAGE_RIGHTS_READ, GetCurrentProcess()) != STATUS_SUCCESS) {
            return STATUS_UNSUCCESSFUL;
        }

        if (cl_strlen(Arguments) + 1 != ArgLength) {
            return STATUS_UNSUCCESSFUL;
        }

    }

    if (cl_strlen(ProcessPath) + 1 != PathLength) {
        return STATUS_UNSUCCESSFUL;
    }

    SystemDrive = IomuGetSystemPartitionPath();

    strcpy(absolutePath, SystemDrive);
    sprintf(absolutePath, "%sApplications\\%s", absolutePath, ProcessPath);

    Status = ProcessCreate(absolutePath, Arguments, &pProcess);

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS_HANDLE processHandle = (PPROCESS_HANDLE)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(PROCESS_HANDLE), TAG_CREATE_PROCESS, PAGE_SIZE);

    if (processHandle == NULL) {
        LOG_ERROR("Process Create - ExAllocatePoolWithTag");
        return STATUS_UNSUCCESSFUL;
    }
    else {
        processHandle->Process = pProcess;
        processHandle->Handle = HANDLE_ID_INCREMENT;
        HANDLE_ID_INCREMENT += 1;

        InsertTailList(
            &m_processHandleList.ProcessHandleListHead,
            &processHandle->ProcessHandleList);
        *ProcessHandle = processHandle->Handle;
    }

    //LOG_WARNING("syscall process create: SUCCESS, id: %d\n", processHandle->Handle);
    return STATUS_SUCCESS;
}

// SyscallIdProcessGetPid
STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID*                    ProcessId
)
{
    STATUS Status;
    PPROCESS pProcess;

    // thread handle is invalid so you have to look for the current thread's id
    if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
        pProcess = GetCurrentProcess();

        if (pProcess == NULL) {
            return STATUS_UNSUCCESSFUL; // nothing to return
        }

        *ProcessId = ProcessGetId(pProcess);
        return STATUS_SUCCESS;
    }

    // if we have a valid handle
    Status = FindProcessByUM_HANDLE(ProcessHandle, &pProcess);

    if (Status == STATUS_SUCCESS) {
        *ProcessId = ProcessGetId(pProcess);
    }

    return Status;
}

// SyscallIdProcessWaitForTermination
STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{
    if (TerminationStatus == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (MmuIsBufferValid((STATUS*)TerminationStatus, sizeof(STATUS), PAGE_RIGHTS_WRITE, GetCurrentProcess()) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    PPROCESS pProcess;
    STATUS Status;

    Status = FindProcessByUM_HANDLE(ProcessHandle, &pProcess);

    if (Status != STATUS_SUCCESS || pProcess == NULL) {

        return Status;
    }

    (pProcess, TerminationStatus);

    return Status;
}

// SyscallIdProcessCloseHandle
STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
    STATUS Status = CloseAndDeleteProcessByUM_HANDLE(ProcessHandle);

    return Status;
}

// FILES
// SyscallIdFileCreate
STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE*              FileHandle
)
{
    if (!SUCCEEDED(MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_READ, GetCurrentProcess())))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (Path == NULL || FileHandle == NULL || PathLength <= 1) {
        return STATUS_UNSUCCESSFUL;
    }

    PFILE_OBJECT pFile;
    STATUS Status;
    //const char* SystemDrive;
    char absolutePath[MAX_PATH];


    if (Path == strrchr(Path, '\\')) {
        sprintf(absolutePath, "C:\\%s", Path);
    }
    else {
        strcpy(absolutePath, Path);
    }

    //LOGP_ERROR("absolutePath0: %s\n", absolutePath);

    //SystemDrive = IomuGetSystemPartitionPath();
    //LOGP_ERROR("System drive: %s\n", SystemDrive);
    //strcpy(absolutePath, SystemDrive);
    //LOGP_ERROR("absolutePath: %s\n", absolutePath);
    //sprintf(absolutePath, "%sApplications\\%s", absolutePath, Path);
    //LOGP_ERROR("absolutePath2: %s\n", absolutePath);

    Status = IoCreateFile(&pFile, absolutePath, Directory, Create, FALSE);

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    PFILE_HANDLE fileHandle = (PFILE_HANDLE)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(FILE_HANDLE), TAG_CREATE_FILE, PAGE_SIZE);

    if (fileHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    else {
        fileHandle->File = pFile;
        fileHandle->Handle = HANDLE_ID_INCREMENT;
        HANDLE_ID_INCREMENT += 1;

        InsertTailList(
            &m_fileHandleList.FileHandleListHead,
            &fileHandle->FileHandleList);
        *FileHandle = fileHandle->Handle;
    }

    return STATUS_SUCCESS;
}

// SyscallIdFileClose
STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        return STATUS_SUCCESS;
    }

    STATUS Status;
    Status = CloseAndDeleteFileByUM_HANDLE(FileHandle);

    return Status;
}

// SyscallIdFileRead
STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                           Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD*                      BytesRead
)
{
    if (FileHandle == UM_INVALID_HANDLE_VALUE ||
        FileHandle == UM_FILE_HANDLE_STDOUT ||
        FileHandle > 64 ||
        FileHandle < 0)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (BytesToRead == 0) {
        *BytesRead = 0;
        return STATUS_SUCCESS;
    }

    if (!SUCCEEDED(MmuIsBufferValid(Buffer, sizeof(Buffer), PAGE_RIGHTS_READ, GetCurrentProcess())))
    {
        return STATUS_UNSUCCESSFUL;
    }

    PFILE_OBJECT pFile;
    STATUS Status;
    
    Status = FindFileByUM_HANDLE(FileHandle, &pFile);

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    Status = IoReadFile(pFile, BytesToRead, NULL, Buffer, BytesRead);
    
    return Status;
}

// SyscallIdFileWrite
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD*                      BytesWritten
)
{   

    if (BytesToWrite == 0) {
        *BytesWritten = 0;
        return STATUS_SUCCESS;
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        *BytesWritten = BytesToWrite;
        LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

//THREADS
STATUS
SyscallThreadExit(
    IN      STATUS                  ExitStatus
)
{
    ThreadExit(ExitStatus);
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadCreate(
    IN      PFUNC_ThreadStart       StartFunction,
    IN_OPT  PVOID                   Context,
    OUT     UM_HANDLE* ThreadHandle
)
{
    //UNREFERENCED_PARAMETER(StartFunction);
    //UNREFERENCED_PARAMETER(Context);
    //UNREFERENCED_PARAMETER(ThreadHandle);
    
    struct _THREAD* pThread;
    PPROCESS pProcess;
    STATUS Status;

    if (StartFunction == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        return STATUS_UNSUCCESSFUL;
    }

    pProcess = GetCurrentProcess();

    if (MmuIsBufferValid((PVOID)StartFunction, sizeof(PFUNC_ThreadStart), PAGE_RIGHTS_ALL, pProcess) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }
    
    Status = ThreadCreateEx("Thread from syscall create thread", ThreadPriorityDefault, StartFunction, Context, &pThread, pProcess);

    if (Status != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    //PTHREAD_HANDLE threadHandle = (PTHREAD_HANDLE)malloc(1 * sizeof(THREAD_HANDLE));
    PTHREAD_HANDLE threadHandle = (PTHREAD_HANDLE)ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(THREAD_HANDLE), TAG_CREATE_THREAD, PAGE_SIZE); // 0 or pagesize


    if (threadHandle == NULL) {
        LOG_ERROR("ExAllocatePoolWithTag");
        return STATUS_UNSUCCESSFUL;
    }
    else {
        threadHandle->Thread = pThread;
        threadHandle->Handle = HANDLE_ID_INCREMENT;
        HANDLE_ID_INCREMENT += 1;

        InsertTailList(
            &m_threadHandleList.ThreadHandleList,
            &threadHandle->ThreadHandleList);
        *ThreadHandle = threadHandle->Handle;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT  UM_HANDLE               ThreadHandle,
    OUT     TID*                    ThreadId
)
{
    STATUS Status;
    PTHREAD pThread;

    // thread handle is invalid so you have to look for the current thread's id
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE) {
        pThread = GetCurrentThread();

        if (pThread == NULL) {
            return STATUS_UNSUCCESSFUL; // nothing to return
        }

        *ThreadId = ThreadGetId(pThread);
        return STATUS_SUCCESS;
    }

    // if we have a valid handle
    Status = FindThreadByUM_HANDLE(ThreadHandle, &pThread);

    if (Status == STATUS_SUCCESS) {
        *ThreadId = ThreadGetId(pThread);
    }

    return Status;
}

STATUS
SyscallThreadWaitForTermination(
    IN      UM_HANDLE               ThreadHandle,
    OUT     STATUS*                 TerminationStatus
)
{
    PTHREAD pThread;
    STATUS Status;

    Status = FindThreadByUM_HANDLE(ThreadHandle, &pThread);

    if (Status != STATUS_SUCCESS) {

        return Status;
    }

    ThreadWaitForTermination(pThread, TerminationStatus);

    return Status;
}

STATUS
SyscallThreadCloseHandle(
    IN      UM_HANDLE               ThreadHandle
)
{
    STATUS Status = CloseAndDeleteThreadByUM_HANDLE(ThreadHandle);

    return Status;
}

STATUS
FindThreadByUM_HANDLE(
    IN UM_HANDLE        ThreadHandle,
    OUT PTHREAD*        pThread
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    BOOLEAN Found = FALSE;
    PTHREAD_HANDLE pThreadForIterator;

    ListIteratorInit(&m_threadHandleList.ThreadHandleList, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pThreadForIterator = CONTAINING_RECORD(pListEntry, THREAD_HANDLE, ThreadHandleList);    // it takes the thread handle value from the list entry value

        if (pThreadForIterator->Handle == ThreadHandle) {
            *pThread = pThreadForIterator->Thread;
            Found = TRUE;
            break;
        } 
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
CloseAndDeleteThreadByUM_HANDLE(
    IN UM_HANDLE        ThreadHandle
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    BOOLEAN Found = FALSE;
    PTHREAD_HANDLE pThreadForIterator;

    ListIteratorInit(&m_threadHandleList.ThreadHandleList, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pThreadForIterator = CONTAINING_RECORD(pListEntry, THREAD_HANDLE, ThreadHandleList);    // it takes the thread handle value from the list entry value

        if (pThreadForIterator->Handle == ThreadHandle) {
            ThreadCloseHandle(pThreadForIterator->Thread);  //close handle before deleting
            RemoveEntryList(pListEntry);
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
FindProcessByUM_HANDLE(
    IN UM_HANDLE        ProcessHandle,
    OUT PPROCESS*       pProcess
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    BOOLEAN Found = FALSE;
    PPROCESS_HANDLE pProcessForIterator;

    ListIteratorInit(&m_processHandleList.ProcessHandleListHead, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pProcessForIterator = CONTAINING_RECORD(pListEntry, PROCESS_HANDLE, ProcessHandleList);    // it takes the thread handle value from the list entry value

        if (pProcessForIterator->Handle == ProcessHandle) {
            *pProcess = pProcessForIterator->Process;
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
CloseAndDeleteProcessByUM_HANDLE(
    IN UM_HANDLE        ProcessHandle
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    BOOLEAN Found = FALSE;
    PPROCESS_HANDLE pProcessForIterator;

    ListIteratorInit(&m_processHandleList.ProcessHandleListHead, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pProcessForIterator = CONTAINING_RECORD(pListEntry, PROCESS_HANDLE, ProcessHandleList);    // it takes the thread handle value from the list entry value

        if (pProcessForIterator->Handle == ProcessHandle) {
            ProcessCloseHandle(pProcessForIterator->Process);
            RemoveEntryList(pListEntry);
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
FindFileByUM_HANDLE(
    IN UM_HANDLE                 FileHandle,
    OUT PFILE_OBJECT*            pFile
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    BOOLEAN Found = FALSE;
    PFILE_HANDLE pFileForIterator;

    ListIteratorInit(&m_fileHandleList.FileHandleListHead, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pFileForIterator = CONTAINING_RECORD(pListEntry, FILE_HANDLE, FileHandleList);    // it takes the thread handle value from the list entry value

        if (pFileForIterator->Handle == FileHandle) {
            *pFile = pFileForIterator->File;
            Found = TRUE;
            break;
        }
    }

    if (Found) {
        return STATUS_SUCCESS;
    }
    else {
        return STATUS_NO_DATA_AVAILABLE;
    }
}

STATUS
CloseAndDeleteFileByUM_HANDLE(
    IN UM_HANDLE                 FileHandle
) {
    LIST_ITERATOR ListIterator;
    PLIST_ENTRY pListEntry; // i
    PFILE_HANDLE pFileForIterator;
    STATUS Status;
    ListIteratorInit(&m_fileHandleList.FileHandleListHead, &ListIterator);

    while ((pListEntry = ListIteratorNext(&ListIterator)) != NULL) {

        pFileForIterator = CONTAINING_RECORD(pListEntry, FILE_HANDLE, FileHandleList);    // it takes the thread handle value from the list entry value

        if (pFileForIterator->Handle == FileHandle) {
            RemoveEntryList(pListEntry);
            Status = IoCloseFile(pFileForIterator->File);
            if (!SUCCEEDED(Status)) {
                return STATUS_UNSUCCESSFUL;
            }
            else {
                return Status;
            }
            break;
        }
    }

    return STATUS_UNSUCCESSFUL;
}