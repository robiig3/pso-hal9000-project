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

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION
#define APP_TAG 'PPA'
#define APP_NEW_TAG 'PPAN'

static struct _PROCESS_HANDLE_LIST m_processHandleList;
static struct _FILE_HANDLE_LIST m_fileHandleList;

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
    // initializam lista de ProcessHandle
    InitializeListHead(&m_processHandleList.ProcessHandleListHead);
    InitializeListHead(&m_fileHandleList.FileHandleListHead);
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
// SyscallIdProcessExit
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS process = GetCurrentProcess();
    process->TerminationStatus = ExitStatus;
    ProcessTerminate(process);
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
    UNREFERENCED_PARAMETER(ProcessPath);
    UNREFERENCED_PARAMETER(PathLength);
    UNREFERENCED_PARAMETER(Arguments);
    UNREFERENCED_PARAMETER(ArgLength);
    UNREFERENCED_PARAMETER(ProcessHandle);
    /*
    PPROCESS Process;
    STATUS status;

    if (ProcessPath == NULL || ProcessHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
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

    */

    return STATUS_SUCCESS;
}

// SyscallIdProcessGetPid
STATUS
SyscallProcessGetPid(
    IN_OPT  UM_HANDLE               ProcessHandle,
    OUT     PID* ProcessId
)
{
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ProcessId);
    return STATUS_SUCCESS;
}

// SyscallIdProcessWaitForTermination
STATUS
SyscallProcessWaitForTermination(
    IN      UM_HANDLE               ProcessHandle,
    OUT     STATUS* TerminationStatus
)
{
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(TerminationStatus);
    return STATUS_SUCCESS;
}

// SyscallIdProcessCloseHandle
STATUS
SyscallProcessCloseHandle(
    IN      UM_HANDLE               ProcessHandle
)
{
    UNREFERENCED_PARAMETER(ProcessHandle);
    return STATUS_SUCCESS;
}

// SyscallIdFileCreate
STATUS
SyscallFileCreate(
    IN_READS_Z(PathLength)
    char* Path,
    IN          QWORD                   PathLength,
    IN          BOOLEAN                 Directory,
    IN          BOOLEAN                 Create,
    OUT         UM_HANDLE* FileHandle
)
{
    UNREFERENCED_PARAMETER(Path);
    UNREFERENCED_PARAMETER(PathLength);
    UNREFERENCED_PARAMETER(Directory);
    UNREFERENCED_PARAMETER(Create);
    UNREFERENCED_PARAMETER(FileHandle);
    return STATUS_SUCCESS;
}

// SyscallIdFileClose
STATUS
SyscallFileClose(
    IN          UM_HANDLE               FileHandle
)
{
    UNREFERENCED_PARAMETER(FileHandle);
    return STATUS_SUCCESS;
}

// SyscallIdFileRead
STATUS
SyscallFileRead(
    IN  UM_HANDLE                   FileHandle,
    OUT_WRITES_BYTES(BytesToRead)
    PVOID                       Buffer,
    IN  QWORD                       BytesToRead,
    OUT QWORD* BytesRead
)
{
    UNREFERENCED_PARAMETER(FileHandle);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BytesToRead);
    UNREFERENCED_PARAMETER(BytesRead);

    //STATUS status;
    /*
    if (BytesRead == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    if (BytesToRead == 0) {
        *BytesRead = 0;
        return STATUS_SUCCESS;
    }

    if (MmuIsBufferValid(
        Buffer,
        BytesToRead,
        PAGE_RIGHTS_READ,
        GetCurrentProcess()
    ) != STATUS_SUCCESS) {
        return STATUS_UNSUCCESSFUL;
    }

    //status = IoReadFile(FileObject, BytesToRead, NULL, Buffer, BytesRead);
    */

    return STATUS_SUCCESS;
}

// SyscallIdFileWrite
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                       Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    UNREFERENCED_PARAMETER(FileHandle);
    UNREFERENCED_PARAMETER(BytesWritten);
    REFERENCED_PARAMETER(Buffer);
    REFERENCED_PARAMETER(BytesToWrite);
    /*
    MmuIsBufferValid(
        Buffer,
        BytesToWrite,
        PAGE_RIGHTS_WRITE,
        GetCurrentProcess()
    );

    if (FileHandle == UM_FILE_HANDLE_STDOUT) {
        LOG("[%s]:[%s]", ProcessGetName(NULL), Buffer);
    }

    *BytesWritten = BytesToWrite;
    */
    return STATUS_SUCCESS;
}
