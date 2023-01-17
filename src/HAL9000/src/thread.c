#include "HAL9000.h"
#include "thread_internal.h"
#include "synch.h"
#include "cpumu.h"
#include "ex_event.h"
#include "core.h"
#include "vmm.h"
#include "process_internal.h"
#include "isr.h"
#include "gdtmu.h"
#include "pe_exports.h"

#define TID_INCREMENT               4

#define THREAD_TIME_SLICE           1

extern void ThreadStart();

typedef
void
(__cdecl FUNC_ThreadSwitch)(
    OUT_PTR         PVOID*          OldStack,
    IN              PVOID           NewStack
    );

extern FUNC_ThreadSwitch            ThreadSwitch;

typedef struct _THREAD_SYSTEM_DATA
{
    LOCK                AllThreadsLock;

    _Guarded_by_(AllThreadsLock)
    LIST_ENTRY          AllThreadsList;

    LOCK                ReadyThreadsLock;

    _Guarded_by_(ReadyThreadsLock)
    LIST_ENTRY          ReadyThreadsList;

    _Guarded_by_(ReadyThreadsLock)
    THREAD_PRIORITY     RunningThreadsMinPriority;
} THREAD_SYSTEM_DATA, *PTHREAD_SYSTEM_DATA;

static THREAD_SYSTEM_DATA m_threadSystemData;

__forceinline
static
TID
_ThreadSystemGetNextTid(
    void
    )
{
    static volatile TID __currentTid = 0;

    return _InterlockedExchangeAdd64(&__currentTid, TID_INCREMENT);
}

static
STATUS
_ThreadInit(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    OUT_PTR     PTHREAD*            Thread,
    IN          BOOLEAN             AllocateKernelStack
    );

static
STATUS
_ThreadSetupInitialState(
    IN      PTHREAD             Thread,
    IN      PVOID               StartFunction,
    IN      QWORD               FirstArgument,
    IN      QWORD               SecondArgument,
    IN      BOOLEAN             KernelStack
    );

static
STATUS
_ThreadSetupMainThreadUserStack(
    IN      PVOID               InitialStack,
    OUT     PVOID*              ResultingStack,
    IN      PPROCESS            Process
    );


REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(m_threadSystemData.ReadyThreadsLock)
static
void
_ThreadSchedule(
    void
    );

REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(m_threadSystemData.ReadyThreadsLock)
void
ThreadCleanupPostSchedule(
    void
    );

REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
static
_Ret_notnull_
PTHREAD
_ThreadGetReadyThread(
    void
    );

static
void
_ThreadForcedExit(
    void
    );

static
void
_ThreadReference(
    INOUT   PTHREAD                 Thread
    );

static
void
_ThreadDereference(
    INOUT   PTHREAD                 Thread
    );

static FUNC_FreeFunction            _ThreadDestroy;

static
void
_ThreadKernelFunction(
    IN      PFUNC_ThreadStart       Function,
    IN_OPT  PVOID                   Context
    );

static FUNC_ThreadStart     _IdleThread;

void
_No_competing_thread_
ThreadSystemPreinit(
    void
    )
{
    memzero(&m_threadSystemData, sizeof(THREAD_SYSTEM_DATA));

    InitializeListHead(&m_threadSystemData.AllThreadsList);
    LockInit(&m_threadSystemData.AllThreadsLock);

    InitializeListHead(&m_threadSystemData.ReadyThreadsList);
    LockInit(&m_threadSystemData.ReadyThreadsLock);
}

STATUS
ThreadSystemInitMainForCurrentCPU(
    void
    )
{
    STATUS status;
    PPCPU pCpu;
    char mainThreadName[MAX_PATH];
    PTHREAD pThread;
    PPROCESS pProcess;

    LOG_FUNC_START;

    status = STATUS_SUCCESS;
    pCpu = GetCurrentPcpu();
    pThread = NULL;
    pProcess = ProcessRetrieveSystemProcess();

    ASSERT( NULL != pCpu );

    snprintf( mainThreadName, MAX_PATH, "%s-%02x", "main", pCpu->ApicId );

    status = _ThreadInit(mainThreadName, ThreadPriorityDefault, &pThread, FALSE);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadInit", status );
        return status;
    }
    LOGPL("_ThreadInit succeeded\n");

    pThread->InitialStackBase = pCpu->StackTop;
    pThread->StackSize = pCpu->StackSize;

    pThread->State = ThreadStateRunning;
    SetCurrentThread(pThread);

    // In case of the main thread of the BSP the process will be NULL so we need to handle that case
    // When the system process will be initialized it will insert into its thread list the current thread (which will
    // be the main thread of the BSP)
    if (pProcess != NULL)
    {
        ProcessInsertThreadInList(pProcess, pThread);
    }

    LOG_FUNC_END;

    return status;
}

STATUS
ThreadSystemInitIdleForCurrentCPU(
    void
    )
{
    EX_EVENT idleStarted;
    STATUS status;
    PPCPU pCpu;
    char idleThreadName[MAX_PATH];
    PTHREAD idleThread;

    ASSERT( INTR_OFF == CpuIntrGetState() );

    LOG_FUNC_START_THREAD;

    status = STATUS_SUCCESS;
    pCpu = GetCurrentPcpu();

    ASSERT(NULL != pCpu);

    status = ExEventInit(&idleStarted, ExEventTypeSynchronization, FALSE);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("EvtInitialize", status);
        return status;
    }
    LOGPL("EvtInitialize succeeded\n");

    snprintf(idleThreadName, MAX_PATH, "%s-%02x", "idle", pCpu->ApicId);

    // create idle thread
    status = ThreadCreate(idleThreadName,
                          ThreadPriorityDefault,
                          _IdleThread,
                          &idleStarted,
                          &idleThread
                          );
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("ThreadCreate", status);
        return status;
    }
    LOGPL("ThreadCreate for IDLE thread succeeded\n");

    ThreadCloseHandle(idleThread);
    idleThread = NULL;

    LOGPL("About to enable interrupts\n");

    // lets enable some interrupts :)
    CpuIntrEnable();

    LOGPL("Interrupts enabled :)\n");

    // wait for idle thread
    LOG_TRACE_THREAD("Waiting for idle thread signal\n");
    ExEventWaitForSignal(&idleStarted);
    LOG_TRACE_THREAD("Received idle thread signal\n");

    LOG_FUNC_END_THREAD;

    return status;
}

STATUS
ThreadCreate(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    IN          PFUNC_ThreadStart   Function,
    IN_OPT      PVOID               Context,
    OUT_PTR     PTHREAD*            Thread
    )
{
    return ThreadCreateEx(Name,
                          Priority,
                          Function,
                          Context,
                          Thread,
                          ProcessRetrieveSystemProcess());
}

STATUS
ThreadCreateEx(
    IN_Z        char* Name,
    IN          THREAD_PRIORITY     Priority,
    IN          PFUNC_ThreadStart   Function,
    IN_OPT      PVOID               Context,
    OUT_PTR     PTHREAD* Thread,
    INOUT       struct _PROCESS* Process
)
{
    STATUS status;
    PTHREAD pThread;
    PPCPU pCpu;
    BOOLEAN bProcessIniialThread;
    PVOID pStartFunction;
    QWORD firstArg;
    QWORD secondArg;

    if (NULL == Name)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (NULL == Function)
    {
        return STATUS_INVALID_PARAMETER3;
    }

    if (NULL == Thread)
    {
        return STATUS_INVALID_PARAMETER5;
    }

    if (NULL == Process)
    {
        return STATUS_INVALID_PARAMETER6;
    }

    status = STATUS_SUCCESS;
    pThread = NULL;
    pCpu = GetCurrentPcpu();
    bProcessIniialThread = FALSE;
    pStartFunction = NULL;
    firstArg = 0;
    secondArg = 0;

    ASSERT(NULL != pCpu);

    status = _ThreadInit(Name, Priority, &pThread, TRUE);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadInit", status);
        return status;
    }

    ProcessInsertThreadInList(Process, pThread);

    // the reference must be done outside _ThreadInit
    _ThreadReference(pThread);

    if (!Process->PagingData->Data.KernelSpace)
    {
        // Create user-mode stack
        pThread->UserStack = MmuAllocStack(STACK_DEFAULT_SIZE,
            TRUE,
            FALSE,
            Process);
        if (pThread->UserStack == NULL)
        {
            status = STATUS_MEMORY_CANNOT_BE_COMMITED;
            LOG_FUNC_ERROR_ALLOC("MmuAllocStack", STACK_DEFAULT_SIZE);
            return status;
        }

        bProcessIniialThread = (Function == Process->HeaderInfo->Preferred.AddressOfEntryPoint);

        // We are the first thread => we must pass the argc and argv parameters
        // and the whole command line which spawned the process
        if (bProcessIniialThread)
        {
            // It's one because we already incremented it when we called ProcessInsertThreadInList earlier
            ASSERT(Process->NumberOfThreads == 1);

            status = _ThreadSetupMainThreadUserStack(pThread->UserStack,
                &pThread->UserStack,
                Process);
            if (!SUCCEEDED(status))
            {
                LOG_FUNC_ERROR("_ThreadSetupUserStack", status);
                return status;
            }
        }
        else
        {
            pThread->UserStack = (PVOID)PtrDiff(pThread->UserStack, SHADOW_STACK_SIZE + sizeof(PVOID));
        }

        pStartFunction = (PVOID)(bProcessIniialThread ? Process->HeaderInfo->Preferred.AddressOfEntryPoint : Function);
        firstArg = (QWORD)(bProcessIniialThread ? Process->NumberOfArguments : (QWORD)Context);
        secondArg = (QWORD)(bProcessIniialThread ? PtrOffset(pThread->UserStack, SHADOW_STACK_SIZE + sizeof(PVOID)) : 0);
    }
    else
    {
        // Kernel mode

        // warning C4152: nonstandard extension, function/data pointer conversion in expression
#pragma warning(suppress:4152)
        pStartFunction = _ThreadKernelFunction;

        firstArg = (QWORD)Function;
        secondArg = (QWORD)Context;
    }

    status = _ThreadSetupInitialState(pThread,
        pStartFunction,
        firstArg,
        secondArg,
        Process->PagingData->Data.KernelSpace);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadSetupInitialState", status);
        return status;
    }

    if (NULL == pCpu->ThreadData.IdleThread)
    {
        pThread->State = ThreadStateReady;

        // this is the IDLE thread creation
        pCpu->ThreadData.IdleThread = pThread;
    }
    else
    {
        ThreadUnblock(pThread);
    }

    *Thread = pThread;

    return status;
}
void
ThreadTick(
    void
    )
{
    PPCPU pCpu = GetCurrentPcpu();
    PTHREAD pThread = GetCurrentThread();

    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT( NULL != pCpu);

    LOG_TRACE_THREAD("Thread tick\n");
    if (pCpu->ThreadData.IdleThread == pThread)
    {
        pCpu->ThreadData.IdleTicks++;
    }
    else
    {
        pCpu->ThreadData.KernelTicks++;
    }
    pThread->TickCountCompleted++;

    if (++pCpu->ThreadData.RunningThreadTicks >= THREAD_TIME_SLICE)
    {
        LOG_TRACE_THREAD("Will yield on return\n");
        pCpu->ThreadData.YieldOnInterruptReturn = TRUE;
    }
}

void
ThreadYield(
    void
    )
{
    INTR_STATE dummyState;
    INTR_STATE oldState;
    PTHREAD pThread = GetCurrentThread();
    PPCPU pCpu;
    BOOLEAN bForcedYield;

    ASSERT( NULL != pThread);

    oldState = CpuIntrDisable();

    pCpu = GetCurrentPcpu();

    ASSERT( NULL != pCpu );

    bForcedYield = pCpu->ThreadData.YieldOnInterruptReturn;
    pCpu->ThreadData.YieldOnInterruptReturn = FALSE;

    if (THREAD_FLAG_FORCE_TERMINATE_PENDING == _InterlockedAnd(&pThread->Flags, MAX_DWORD))
    {
        _ThreadForcedExit();
        NOT_REACHED;
    }

    LockAcquire(&m_threadSystemData.ReadyThreadsLock, &dummyState);
    if (pThread != pCpu->ThreadData.IdleThread)
    {
        InsertOrderedList(&m_threadSystemData.ReadyThreadsList, &pThread->ReadyList, _ThreadComparePriorityReadyList, NULL);
    }
    if (!bForcedYield)
    {
        pThread->TickCountEarly++;
    }
    pThread->State = ThreadStateReady;
    _ThreadSchedule();
    ASSERT( !LockIsOwner(&m_threadSystemData.ReadyThreadsLock));
    LOG_TRACE_THREAD("Returned from _ThreadSchedule\n");

    CpuIntrSetState(oldState);
}

void
ThreadBlock(
    void
    )
{
    INTR_STATE oldState;
    PTHREAD pCurrentThread;

    pCurrentThread = GetCurrentThread();

    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT(LockIsOwner(&pCurrentThread->BlockLock));

    if (THREAD_FLAG_FORCE_TERMINATE_PENDING == _InterlockedAnd(&pCurrentThread->Flags, MAX_DWORD))
    {
        _ThreadForcedExit();
        NOT_REACHED;
    }

    pCurrentThread->TickCountEarly++;
    pCurrentThread->State = ThreadStateBlocked;
    LockAcquire(&m_threadSystemData.ReadyThreadsLock, &oldState);
    _ThreadSchedule();
    ASSERT( !LockIsOwner(&m_threadSystemData.ReadyThreadsLock));
}

void
ThreadUnblock(
    IN      PTHREAD              Thread
    )
{
    INTR_STATE oldState;
    INTR_STATE dummyState;

    ASSERT(NULL != Thread);

    LockAcquire(&Thread->BlockLock, &oldState);

    ASSERT(ThreadStateBlocked == Thread->State);

    LockAcquire(&m_threadSystemData.ReadyThreadsLock, &dummyState);
    InsertOrderedList(&m_threadSystemData.ReadyThreadsList, &Thread->ReadyList, _ThreadComparePriorityReadyList, NULL);
    Thread->State = ThreadStateReady;
    LockRelease(&m_threadSystemData.ReadyThreadsLock, dummyState );
    LockRelease(&Thread->BlockLock, oldState);
}

void
ThreadExit(
    IN      STATUS              ExitStatus
    )
{
    PTHREAD pThread;
    INTR_STATE oldState;

    LOG_FUNC_START_THREAD;

    pThread = GetCurrentThread();

    CpuIntrDisable();

    if (LockIsOwner(&pThread->BlockLock))
    {
        LockRelease(&pThread->BlockLock, INTR_OFF);
    }

    pThread->State = ThreadStateDying;
    pThread->ExitStatus = ExitStatus;
    ExEventSignal(&pThread->TerminationEvt);

    ProcessNotifyThreadTermination(pThread);

    LockAcquire(&m_threadSystemData.ReadyThreadsLock, &oldState);
    _ThreadSchedule();
    NOT_REACHED;
}

BOOLEAN
ThreadYieldOnInterrupt(
    void
    )
{
    return GetCurrentPcpu()->ThreadData.YieldOnInterruptReturn;
}

void
ThreadTakeBlockLock(
    void
    )
{
    INTR_STATE dummyState;

    LockAcquire(&GetCurrentThread()->BlockLock, &dummyState);
}

void
ThreadWaitForTermination(
    IN      PTHREAD             Thread,
    OUT     STATUS*             ExitStatus
    )
{
    ASSERT( NULL != Thread );
    ASSERT( NULL != ExitStatus);

    ExEventWaitForSignal(&Thread->TerminationEvt);

    *ExitStatus = Thread->ExitStatus;
}

void
ThreadCloseHandle(
    INOUT   PTHREAD             Thread
    )
{
    ASSERT( NULL != Thread);

    _ThreadDereference(Thread);
}

void
ThreadTerminate(
    INOUT   PTHREAD             Thread
    )
{
    ASSERT( NULL != Thread );

    // it's not a problem if the thread already finished
    _InterlockedOr(&Thread->Flags, THREAD_FLAG_FORCE_TERMINATE_PENDING );
}

const
char*
ThreadGetName(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    return (NULL != pThread) ? pThread->Name : "";
}

TID
ThreadGetId(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    return (NULL != pThread) ? pThread->Id : 0;
}

THREAD_PRIORITY
ThreadGetPriority(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    if (pThread->RealPriority <= pThread->Priority) {
        return (NULL != pThread) ? pThread->Priority : 0;
    }

    return pThread->RealPriority;
}

void
ThreadSetPriority(
    IN      THREAD_PRIORITY     NewPriority
    )
{
    ASSERT(ThreadPriorityLowest <= NewPriority && NewPriority <= ThreadPriorityMaximum);

    if (GetCurrentThread()->Priority < NewPriority) {
        GetCurrentThread()->RealPriority = NewPriority;
    }
    else {
        GetCurrentThread()->Priority = NewPriority;
        GetCurrentThread()->RealPriority = NewPriority;
    }
}

STATUS
ThreadExecuteForEachThreadEntry(
    IN      PFUNC_ListFunction  Function,
    IN_OPT  PVOID               Context
    )
{
    STATUS status;
    INTR_STATE oldState;

    if (NULL == Function)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    status = STATUS_SUCCESS;

    LockAcquire(&m_threadSystemData.AllThreadsLock, &oldState);
    status = ForEachElementExecute(&m_threadSystemData.AllThreadsList,
                                   Function,
                                   Context,
                                   FALSE
                                   );
    LockRelease(&m_threadSystemData.AllThreadsLock, oldState );

    return status;
}

void
SetCurrentThread(
    IN      PTHREAD     Thread
    )
{
    PPCPU pCpu;

    __writemsr(IA32_FS_BASE_MSR, Thread);

    pCpu = GetCurrentPcpu();
    ASSERT(pCpu != NULL);

    pCpu->ThreadData.CurrentThread = Thread->Self;
    if (NULL != Thread->Self)
    {
        pCpu->StackTop = Thread->InitialStackBase;
        pCpu->StackSize = Thread->StackSize;
        pCpu->Tss.Rsp[0] = (QWORD) Thread->InitialStackBase;
    }
}

static
STATUS
_ThreadInit(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    OUT_PTR     PTHREAD*            Thread,
    IN          BOOLEAN             AllocateKernelStack
    )
{
    STATUS status;
    PTHREAD pThread;
    DWORD nameLen;
    PVOID pStack;
    INTR_STATE oldIntrState;

    LOG_FUNC_START;

    ASSERT(NULL != Name);
    ASSERT(NULL != Thread);
    ASSERT_INFO(ThreadPriorityLowest <= Priority && Priority <= ThreadPriorityMaximum,
                "Priority is 0x%x\n", Priority);

    status = STATUS_SUCCESS;
    pThread = NULL;
    nameLen = strlen(Name);
    pStack = NULL;

    __try
    {
        pThread = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(THREAD), HEAP_THREAD_TAG, 0);
        if (NULL == pThread)
        {
            LOG_FUNC_ERROR_ALLOC("HeapAllocatePoolWithTag", sizeof(THREAD));
            status = STATUS_HEAP_INSUFFICIENT_RESOURCES;
            __leave;
        }

        RfcPreInit(&pThread->RefCnt);

        status = RfcInit(&pThread->RefCnt, _ThreadDestroy, NULL);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("RfcInit", status);
            __leave;
        }

        pThread->Self = pThread;

        status = ExEventInit(&pThread->TerminationEvt, ExEventTypeNotification, FALSE);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("ExEventInit", status);
            __leave;
        }

        if (AllocateKernelStack)
        {
            pStack = MmuAllocStack(STACK_DEFAULT_SIZE, TRUE, FALSE, NULL);
            if (NULL == pStack)
            {
                LOG_FUNC_ERROR_ALLOC("MmuAllocStack", STACK_DEFAULT_SIZE);
                status = STATUS_MEMORY_CANNOT_BE_COMMITED;
                __leave;
            }
            pThread->Stack = pStack;
            pThread->InitialStackBase = pStack;
            pThread->StackSize = STACK_DEFAULT_SIZE;
        }

        pThread->Name = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(char)*(nameLen + 1), HEAP_THREAD_TAG, 0);
        if (NULL == pThread->Name)
        {
            LOG_FUNC_ERROR_ALLOC("HeapAllocatePoolWithTag", sizeof(char)*(nameLen + 1));
            status = STATUS_HEAP_INSUFFICIENT_RESOURCES;
            __leave;
        }

        strcpy(pThread->Name, Name);

        pThread->Id = _ThreadSystemGetNextTid();
        pThread->State = ThreadStateBlocked;
        pThread->Priority = Priority;

        LockInit(&pThread->BlockLock);

        LockAcquire(&m_threadSystemData.AllThreadsLock, &oldIntrState);
        InsertTailList(&m_threadSystemData.AllThreadsList, &pThread->AllList);
        LockRelease(&m_threadSystemData.AllThreadsLock, oldIntrState);
    }
    __finally
    {
        if (!SUCCEEDED(status))
        {
            if (NULL != pThread)
            {
                _ThreadDereference(pThread);
                pThread = NULL;
            }
        }

        *Thread = pThread;

        LOG_FUNC_END;
    }

    return status;
}

//  STACK TOP
//  -----------------------------------------------------------------
//  |                                                               |
//  |       Shadow Space                                            |
//  |                                                               |
//  |                                                               |
//  -----------------------------------------------------------------
//  |     Dummy Function RA                                         |
//  ---------------------------------------------------------------------------------
//  |     SS     = DS64Supervisor        | DS64Usermode             |               |
//  -----------------------------------------------------------------               |
//  |     RSP    = &(Dummy Function RA)  | Thread->UserStack        |               |
//  -----------------------------------------------------------------               |
//  |     RFLAGS = RFLAGS_IF | RFLAGS_RESERVED                      |   Interrupt   |
//  -----------------------------------------------------------------     Stack     |
//  |     CS     = CS64Supervisor        | CS64Usermode             |               |
//  -----------------------------------------------------------------               |
//  |     RIP    = _ThreadKernelFunction | AddressOfEntryPoint      |               |
//  ---------------------------------------------------------------------------------
//  |     Thread Start Function                                     |
//  -----------------------------------------------------------------
//  |                                                               |
//  |       PROCESSOR_STATE                                         |
//  |                                                               |
//  |                                                               |
//  -----------------------------------------------------------------
//  STACK BASE <- RSP at ThreadSwitch
static
STATUS
_ThreadSetupInitialState(
    IN      PTHREAD             Thread,
    IN      PVOID               StartFunction,
    IN      QWORD               FirstArgument,
    IN      QWORD               SecondArgument,
    IN      BOOLEAN             KernelStack
    )
{
    STATUS status;
    PVOID* pStack;
    PCOMPLETE_PROCESSOR_STATE pState;
    PINTERRUPT_STACK pIst;

    ASSERT( NULL != Thread );
    ASSERT( NULL != StartFunction);

    status = STATUS_SUCCESS;

    pStack = (PVOID*) Thread->Stack;

    // The kernel function has to have a shadow space and a dummy RA
    pStack = pStack - ( 4 + 1 );

    pStack = (PVOID*) PtrDiff(pStack, sizeof(INTERRUPT_STACK));

    // setup pseudo-interrupt stack
    pIst = (PINTERRUPT_STACK) pStack;

    pIst->Rip = (QWORD) StartFunction;
    if (KernelStack)
    {
        pIst->CS = GdtMuGetCS64Supervisor();
        pIst->Rsp = (QWORD)(pIst + 1);
        pIst->SS = GdtMuGetDS64Supervisor();
    }
    else
    {
        ASSERT(Thread->UserStack != NULL);

        pIst->CS = GdtMuGetCS64Usermode() | RING_THREE_PL;
        pIst->Rsp = (QWORD) Thread->UserStack;
        pIst->SS = GdtMuGetDS64Usermode() | RING_THREE_PL;
    }

    pIst->RFLAGS = RFLAGS_INTERRUPT_FLAG_BIT | RFLAGS_RESERVED_BIT;

    pStack = pStack - 1;

    // warning C4054: 'type cast': from function pointer 'void (__cdecl *)(const PFUNC_ThreadStart,const PVOID)' to data pointer 'PVOID'
#pragma warning(suppress:4054)
    *pStack = (PVOID) ThreadStart;

    pStack = (PVOID*) PtrDiff(pStack, sizeof(COMPLETE_PROCESSOR_STATE));
    pState = (PCOMPLETE_PROCESSOR_STATE) pStack;

    memzero(pState, sizeof(COMPLETE_PROCESSOR_STATE));
    pState->RegisterArea.RegisterValues[RegisterRcx] = FirstArgument;
    pState->RegisterArea.RegisterValues[RegisterRdx] = SecondArgument;

    Thread->Stack = pStack;

    return STATUS_SUCCESS;
}


//  USER STACK TOP
//  -----------------------------------------------------------------
//  |                       Argument N-1                            |
//  -----------------------------------------------------------------
//  |                          ...                                  |
//  -----------------------------------------------------------------
//  |                       Argument 0                              |
//  -----------------------------------------------------------------
//  |                 argv[N-1] = &(Argument N-1)                   |
//  -----------------------------------------------------------------
//  |                          ...                                  |
//  -----------------------------------------------------------------
//  |                 argv[0] = &(Argument 0)                       |
//  -----------------------------------------------------------------
//  |                 Dummy 4th Arg = 0xDEADBEEF                    |
//  -----------------------------------------------------------------
//  |                 Dummy 3rd Arg = 0xDEADBEEF                    |
//  -----------------------------------------------------------------
//  |                 argv = &argv[0]                               |
//  -----------------------------------------------------------------
//  |                 argc = N (Process->NumberOfArguments)         |
//  -----------------------------------------------------------------
//  |                 Dummy RA = 0xDEADC0DE                         |
//  -----------------------------------------------------------------
//  USER STACK BASE
static
STATUS
_ThreadSetupMainThreadUserStack(
    IN      PVOID               InitialStack,
    OUT     PVOID* ResultingStack,
    IN      PPROCESS            Process
)
{

    ASSERT(InitialStack != NULL);
    ASSERT(ResultingStack != NULL);
    ASSERT(Process != NULL);

    // IMPORTANT NOTE 
    //  am adus si modificari in plus INAFARA de ce mi-ati spus sa modific in cod la ora de proiect
    //aceste modificari sunt:
    //inainte valoare ce puneam in stiva acolo unde stocam adrese era de tip QWORD. Acuma am modificat ca sa respect
    //ceea ce este scris in documentatie asa ca unele valori(adrese stocate) sunt acuma ori (void*) ori (char*)

    //apare totusi o PROBLEMA ce sunt sigur de ea, eu daca vreau sa imi introduc in stiva in loc de un PQWORD cu o adresa
    //dummy, un PVOID, tre sa imi creez o variabila si sa ii dau adresa variabilei respective. Nu imi dau seama cat de ok
    //este asta

    //am adus schimbari la bitii de aligment inainte ii lasam liberi si doar incrementam stiva si nu aveau nicio valoare. 
    //acuma pun valoarea 0 la fiecare byte in parte cu care incrementez stiva

    //am mutat totul pe QWORD, nu mai folosesc deloc BYTE(inafara de aligment bytes) ca sa nu ma incurc

    //ca sa fiu sigur ca nu ii problema de acolo, nu mai folosesc nici functia Ptrdiff, am ales sa scad adresele la fel cum
    //fac si la adunarea offsetului

    LOG("Initial stack : 0x%x\n", InitialStack);
    LOG("avion\n");

    // acolesa - aliniamentul nu se poate calcula aici - e depenendet nu doar de lungimea cuvintelor din linia de comanda, 
    // acolesa - ci si de numarul lor si de alti parametri care vor mai fi pusi pe stiva
    // acolesa - adresa unde va fi pusa adresa de return din fc _start, aceea trebuie sa fie multiple de 8, dar nu de 16 (0x10) 
    int aligment; //= strlen(Process->FullCommandLine) % 16;
    //const int al; //= 16 - aligment;
    // acolesa - nu cred ca ai calculat bine ce vine pe stiva - SHADOW_STACK_SIZE e 0x20 adica 32 = 4 * 8, 
    //           deci cuprinde atat cele 2 valori dummy3 si dummy4, cat si argv si argc
    //QWORD stSize = strlen(Process->FullCommandLine) + Process->NumberOfArguments * sizeof(char*) + sizeof(char**) +
    //    SHADOW_STACK_SIZE + sizeof(QWORD) + sizeof(PVOID) + al;
    // acolesa - strlen(Process->FullCommandLine) e OK, doar daca nu ai mai multe spatii intre cuvinte, ci doar cate unul singur
    // acolesa - ceea ce cred ca se intampla, din fericire, in testele actuale
    QWORD stSize = strlen(Process->FullCommandLine) + Process->NumberOfArguments * sizeof(char*) +
        SHADOW_STACK_SIZE + sizeof(PVOID);

    // acolesa - align to 8 (could be 16, also)
    aligment = stSize % 8 == 0 ? 0 : (8 - stSize % 8);
    stSize += aligment;
    // align to 8, but not 16
    aligment = stSize % 16 == 0 ? 8 : 0;
    stSize += aligment;

    PVOID stBuffer = NULL;

    // acolesa - nu as fi dat acum valoare lui ResultingStack - se putea stabili la sfarsit - mai vedem exact cum e atunci
    //*ResultingStack = (PQWORD)InitialStack - stSize;    
    *ResultingStack = (PVOID)PtrDiff(InitialStack, stSize);
    LOG("resulting stack : 0x%x\n", *ResultingStack);

    // acolesa - pentru ca in fc MmuGetSystemVirtualAddressForUserBuffer se face niste alinieri la adresa pagini, 
    // as merge pe valori sigure, pe care le controlez aici - as mapa toata memoria rezervata stivei
    //MmuGetSystemVirtualAddressForUserBuffer(*ResultingStack, stSize, PAGE_RIGHTS_ALL, Process, &stBuffer);
    STATUS status = MmuGetSystemVirtualAddressForUserBuffer((PVOID)PtrDiff(InitialStack, STACK_DEFAULT_SIZE), STACK_DEFAULT_SIZE, PAGE_RIGHTS_ALL, Process, &stBuffer);
    if (!SUCCEEDED(status)) {
        return STATUS_INSUFFICIENT_MEMORY;
    }

    //LOG("resulting stack1 : 0x%x\n", ResultingStack);

    //adaug dummy return address
    QWORD offset = 0;

    // acolesa - salvez valoarea unde e mapata stiva
    PVOID stBufferSaved = stBuffer;

    // acolesa - stBuffer trebuie adus la baza stivei, adica la adresele mari - acum, dupa mapare, e la adrese mici
    //stBuffer = (PQWORD)stBuffer;
    stBuffer = PtrOffset(stBuffer, STACK_DEFAULT_SIZE);

    // acolesa - ca sa revin unde ai vrut tu sa fie stBuffer
    // acolesa - poate mergea si sa las cum ai pus tu in fc de mapare, dar asa sunt mai sigur unde e stBuffer
    stBuffer = (PVOID)PtrDiff(stBuffer, stSize);

    // acolesa - fake return address
    QWORD i1 = 0xDEADC0D0;
    // acolesa - nu cred ca ai inteles ce trebuie facut - pus pe stiva, adica la adresa unde indinva stBuffer, si NU schimbat (aiurea) adresa unde indica stBuffer
    //(PVOID)stBuffer = &i1;
    *(PQWORD)stBuffer = i1; // acolesa - asa e corect

    // acolesa = eu cred ca vrei sa vezi ce e pe stiva la adresa unde indica stBuffer, nu valoare acelei adrese
    //LOG("buffer stack : 0x%x\n", stBuffer); 
    LOG("buffer stack : 0x%x\n", *(PQWORD)stBuffer);

    // acolesa - skip fake ret addresss
    offset = offset + sizeof(PVOID);

    //adaug in stiva argc
    // acolesa - daca faci asa, o dai rau in bara datorita aritmetici cu pointeri
    // acolesa - ce ai scris tu se traduce prin stBuffer += (offset * sizeof(QWORD)) - trebuia facut cast la PBYTE
    // acolesa - dar asta face fc PtrOffset si voi folosi acea functie
    // acolesa - in plus, vad ca tot incrementezi acel offset, dar si actualizezi stBuffer, deci ai o incrementare dubla 
    // acolesa - voi renunta la offset in modificarea lui stBuffer
    //stBuffer = (PQWORD)stBuffer + offset; 
    stBuffer = PtrOffset(stBuffer, sizeof(PVOID));
    *(PQWORD)stBuffer = Process->NumberOfArguments;
    // acolesa - vrei sa vezi ce e pe stiva, probabil
    //LOG("buffer stack1 : 0x%x\n", stBuffer);
    LOG("buffer stack1 : 0x%x\n", *(PQWORD)stBuffer);

    // acolesa - skip - argc, which is a QWORD
    offset = offset + sizeof(QWORD);

    //adaug in stiva argv
    // acolesa - PtrOffset, to skip over argc
    //stBuffer = (PQWORD)stBuffer + offset;
    stBuffer = PtrOffset(stBuffer, sizeof(QWORD));
    // acolesa - e o adresa, deci PVOID sau PQWORD e acelasi lucru ca char* sau char** sau char*** sau .... 
    // acolesa - eu zic sa nu exageram - un pointer e un pointer, indiferenyt la ce pointeaza, tot pe 8 octeti e stocat
    // acolesa - adunand offset la *ResultingStack nu e destul ca sa indici unde incepe argv, 
    // acolesa - pentru ca trebuie sa mai sari si peste cei doi extra paramtri din shadow space
    // *(char***)stBuffer = (char**)ResultingStack + offset;
    *(PQWORD)stBuffer = (QWORD)PtrOffset(*ResultingStack, (offset + 2 * 8));
    LOG("buffer stack2 : 0x%x\n", *(PQWORD)stBuffer);

    // acolesa - skip argv
    offset = offset + sizeof(PQWORD);

    //primul element din shadow space (dummy 3rd argument)

    // acolesa - skip address of argv
    //stBuffer = (PQWORD)stBuffer + offset;
    stBuffer = PtrOffset(stBuffer, sizeof(PQWORD));
    QWORD i2 = 0xDEADBEEF;
    // acolesa - of! of!, de cate ori o sa mai vad asa ceva?
    //(PVOID)stBuffer = &i2;
    *(PQWORD)stBuffer = i2;
    LOG("buffer stack3 : 0x%x\n", *(PQWORD)stBuffer);

    // acolesa - skip dummy3
    offset = offset + sizeof(QWORD);

    //al doilea  element din shadow space (dummy 4rd argument)
    // acolesa - skip dummy3
    //stBuffer = (PQWORD)stBuffer + offset;
    stBuffer = PtrOffset(stBuffer, sizeof(QWORD));
    QWORD i3 = 0xDEADBEEF;
    // acolesa - modificat
    //(PVOID)stBuffer = &i3;
    *(PQWORD)stBuffer = i3;

    LOG("buffer stack4 : 0x%x\n", *(PQWORD)stBuffer);

    // acolesa - skip dummy 4
    offset = offset + sizeof(QWORD);

    // acolesa - cam incurci lucrurile 
    // acolesa - in primul rand ca unde e acum offset, e unde trebuie sa revii, ca sa completezi adresele, deci ar trebui sa retii valoarea curenta a lui offset
    // acolesa - in al doilea rand, ca numarul de '\0' din FullCommanndLine e cuprins in lungimea acelui sir, pentru ca peste spatiile care separa cuvintele, se vor pune '\0'
    // acolesa - o sa comentez ce ai scris tu si o sa incerc sa merg corect, pe aceeasi idee

    //las un spatiu liber pentru a pune ulterior adresele de la argv
    // asa ca am sa stochez in offsetFals de fapt lungimea lui argv + bitii de aligment + elementul '/0' de la fiecare cuvant
    //QWORD offsetFals = al + strlen(Process->FullCommandLine) + Process->NumberOfArguments;//number of argument este de fapt numarul
    //de '/0' de la fiecare end of string
    //offset - offsetFals - adunaInPlus = offsetul in care urmeaza sa pun ADRESELE de la argv.
    QWORD adunaInPlus = 0;

    // acolesa - salvez offsetul curent
    //QWORD offsetForArgv = offset;
    PVOID stBufferArgv = stBuffer;

    //de aici incep partea in care stochez continutul lui argv
    // acolesa - corectat, ca sa sar peste array-ul argv, care are Process->NumberOfArguments elmemente, de tip char* fiecare
    //stBuffer = (PQWORD)stBuffer + offsetFals;
    stBuffer = PtrOffset(stBuffer, sizeof(char*) * Process->NumberOfArguments);

    // acolesa - skip over argv array, where elements of argv (i.e. the strings) will be stored
    offset = offset + sizeof(char*) * Process->NumberOfArguments;

    // acolesa - am vazut cum ai gandit, dar cred ca o sa incerc sa rezolv dintr-o singura trecere prin FullCommandLine

    // acolesa - ca sa nu risc bug-uri in fc ta my_strtok, o sa o folosesc pe cea existenta
    char* command = Process->FullCommandLine;
    const char* pch;
    char* context = NULL;
    //pch = my_strtok(command, " ");
    // acolesa
    pch = strtok_s(command, " ", &context);
    //argv[0]
    //folosesc num ca sa stochez ofsset-ul pentru fiecare cuvant in parte

    // acolesa - tin evidenta elementelor
    QWORD i = 0;
    PVOID stBufferCrtArgv;

    while (pch != NULL)
    {
        stBufferCrtArgv = stBuffer;

        // acolesa - corectat
        //strcpy(*(char**)stBuffer, pch);
        strcpy((char*)stBuffer, pch);
        adunaInPlus = (QWORD)strlen(pch) + 1;

        // acolesa - afisez ce e pe stiva si la ce adresa
        LOG("buffer stackmem1 0x%0x: %s\n", (PVOID)PtrOffset(*ResultingStack, offset), stBuffer);

        // acolesa - jumps where the address of current string must be stored in the argv array
        stBuffer = PtrOffset(stBufferArgv, i * sizeof(char*));
        *(char**)stBuffer = (PVOID)PtrOffset(*ResultingStack, offset); // the address relative to *ResultingStack, which is the address in new process' address space
        i++;

        // acolesa - revin cu stBuffer unde pun sirurile din argv
        //stBuffer = (PQWORD)stBuffer + adunaInPlus;
        stBuffer = PtrOffset(stBufferCrtArgv, adunaInPlus);
        offset = offset + adunaInPlus;

        // acolesa
        pch = strtok_s(NULL, " ", &context);

        //argv[i]
        //pch = my_strtok(NULL, " ");        
        //adunaInPlus = adunaInPlus + (QWORD)strlen(pch) + 1;
        //stBuffer = (PQWORD)stBuffer + adunaInPlus;
        //strcpy(*(char**)stBuffer, pch);
        //LOG("buffer stackmem2 : 0x%x\n", stBuffer);
    }
    //stop, am pus argv in stiva acuma urmeaza sa pun adresele

    //pentru asta tre sa scad din offset
    // offset = offset - offsetFals - adunaInPlus;
    //ok acuma am revenit unde eram initial, adica dupa shadow space.

    // acolesa - cred ca inteleg logica ta, dar, nu va merge, cel putin cu strtok_s, pentru ca ea pune '\0' peste delimitatori si
    // acolesa - la o a doua trecere ptin acelasi sir, nu mai functioneaza - din cate vad, cam la fel faci si tu, 
    // acolesa - ar fi trebuit sa lucrezi pe o copie a lui FullCommandLine
    //in continuare voi lua adresele ce le-am copiat mai sus si le voi pune in stiva
    /*
    char* command1 = Process->FullCommandLine;
    char* pch1;
    pch1 = my_strtok(command1, " ");
    for (DWORD i = 0; i < Process->NumberOfArguments; i++) {
        sprintf((char*)stBuffer, "%u", (PQWORD)stBuffer + offsetFals + strlen(pch1) + 1);
        stBuffer = (PQWORD)stBuffer + sizeof(char*);
        pch1 = my_strtok(NULL, " ");

        LOG("argv adresses : 0x%x\n", stBuffer);
    }

    // acolesa - aliniamentul l-am facut la inceput, nu?
    //aligment bytes
    BYTE alb[16];
    for (int i = 0; i < al; i++) {
        alb[i] = 0;
        *(PBYTE)stBuffer = alb[i];
        offset = offset + sizeof(PBYTE);
        LOG("aligment butes: 0x%x\n", stBuffer);
    }
    LOG("buffer stack offsetal : 0x%x\n", stBuffer);
    //cea ce fac aici ii sa las liber bitii de aligment
    */

    // acolesa - demaparea trebuie facuta de la adresa mica adresa mica!!!!!
    //MmuFreeSystemVirtualAddressForUserBuffer((PVOID)stBuffer);
    MmuFreeSystemVirtualAddressForUserBuffer((PVOID)stBufferSaved);

    return STATUS_SUCCESS;
}

REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(m_threadSystemData.ReadyThreadsLock)
static
void
_ThreadSchedule(
    void
    )
{
    PTHREAD pCurrentThread;
    PTHREAD pNextThread;
    PCPU* pCpu;

    ASSERT(INTR_OFF == CpuIntrGetState());
    ASSERT(LockIsOwner(&m_threadSystemData.ReadyThreadsLock));

    pCurrentThread = GetCurrentThread();
    ASSERT( NULL != pCurrentThread );

    pCpu = GetCurrentPcpu();

    // save previous thread
    pCpu->ThreadData.PreviousThread = pCurrentThread;

    // get next thread
    pNextThread = _ThreadGetReadyThread();
    ASSERT( NULL != pNextThread );

    // if current differs from next
    // => schedule next
    if (pNextThread != pCurrentThread)
    {
        LOG_TRACE_THREAD("Before ThreadSwitch\n");
        LOG_TRACE_THREAD("Current thread: %s\n", pCurrentThread->Name);
        LOG_TRACE_THREAD("Next thread: %s\n", pNextThread->Name);

        if (pCurrentThread->Process != pNextThread->Process)
        {
            MmuChangeProcessSpace(pNextThread->Process);
        }

        // Before any thread is scheduled it executes this function, thus if we set the current
        // thread to be the next one it will be fine - there is no possibility of interrupts
        // appearing to cause inconsistencies
        pCurrentThread->UninterruptedTicks = 0;

        SetCurrentThread(pNextThread);
        ThreadSwitch( &pCurrentThread->Stack, pNextThread->Stack);

        ASSERT(INTR_OFF == CpuIntrGetState());
        ASSERT(LockIsOwner(&m_threadSystemData.ReadyThreadsLock));

        LOG_TRACE_THREAD("After ThreadSwitch\n");
        LOG_TRACE_THREAD("Current: %s\n", pCurrentThread->Name);

        // We cannot log the name of the 'next thread', i.e. the thread which formerly preempted
        // this one because a long time may have passed since then and it may have been destroyed

        // The previous thread may also have been destroyed after it was de-scheduled, we have
        // to be careful before logging its name
        if (pCpu->ThreadData.PreviousThread != NULL)
        {
            LOG_TRACE_THREAD("Prev thread: %s\n", pCpu->ThreadData.PreviousThread->Name);
        }
    }
    else
    {
        pCurrentThread->UninterruptedTicks++;
    }

    ThreadCleanupPostSchedule();
}

REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(m_threadSystemData.ReadyThreadsLock)
void
ThreadCleanupPostSchedule(
    void
    )
{
    PTHREAD prevThread;

    ASSERT(INTR_OFF == CpuIntrGetState());

    GetCurrentPcpu()->ThreadData.RunningThreadTicks = 0;
    prevThread = GetCurrentPcpu()->ThreadData.PreviousThread;

    LockRelease(&m_threadSystemData.ReadyThreadsLock, INTR_OFF);

    if (NULL != prevThread)
    {
        if (LockIsOwner(&prevThread->BlockLock))
        {
            // Unfortunately, we cannot use the inverse condition because it is not always
            // true, i.e. if the previous thread is the idle thread it's not 100% sure that
            // it was previously holding the block hold, it may have been preempted before
            // acquiring it.
            ASSERT(prevThread->State == ThreadStateBlocked
                   || prevThread == GetCurrentPcpu()->ThreadData.IdleThread);

            LOG_TRACE_THREAD("Will release block lock for thread [%s]\n", prevThread->Name);

            _Analysis_assume_lock_held_(prevThread->BlockLock);
            LockRelease(&prevThread->BlockLock, INTR_OFF);
        }
        else if (prevThread->State == ThreadStateDying)
        {
            LOG_TRACE_THREAD("Will dereference thread: [%s]\n", prevThread->Name);

            // dereference thread
            _ThreadDereference(prevThread);
            GetCurrentPcpu()->ThreadData.PreviousThread = NULL;
        }
    }
}

static
STATUS
(__cdecl _IdleThread)(
    IN_OPT      PVOID       Context
    )
{
    PEX_EVENT pEvent;

    LOG_FUNC_START_THREAD;

    ASSERT( NULL != Context);

    pEvent = (PEX_EVENT) Context;
    ExEventSignal(pEvent);

    // warning C4127: conditional expression is constant
#pragma warning(suppress:4127)
    while (TRUE)
    {
        CpuIntrDisable();
        ThreadTakeBlockLock();
        ThreadBlock();

        __sti_and_hlt();
    }

    NOT_REACHED;
}

REQUIRES_EXCL_LOCK(m_threadSystemData.ReadyThreadsLock)
static
_Ret_notnull_
PTHREAD
_ThreadGetReadyThread(
    void
    )
{
    PTHREAD pNextThread;
    PLIST_ENTRY pEntry;
    BOOLEAN bIdleScheduled;

    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT( LockIsOwner(&m_threadSystemData.ReadyThreadsLock));

    pNextThread = NULL;

    pEntry = RemoveHeadList(&m_threadSystemData.ReadyThreadsList);
    if (pEntry == &m_threadSystemData.ReadyThreadsList)
    {
        pNextThread = GetCurrentPcpu()->ThreadData.IdleThread;
        bIdleScheduled = TRUE;
    }
    else
    {
        pNextThread = CONTAINING_RECORD( pEntry, THREAD, ReadyList );

        ASSERT( pNextThread->State == ThreadStateReady );
        bIdleScheduled = FALSE;
    }

    // maybe we shouldn't update idle time each time a thread is scheduled
    // maybe it is enough only every x times
    // or maybe we can update time only on RTC updates
    CoreUpdateIdleTime(bIdleScheduled);

    return pNextThread;
}

static
void
_ThreadForcedExit(
    void
    )
{
    PTHREAD pCurrentThread = GetCurrentThread();

    _InterlockedOr( &pCurrentThread->Flags, THREAD_FLAG_FORCE_TERMINATED );

    ThreadExit(STATUS_JOB_INTERRUPTED);
    NOT_REACHED;
}

static
void
_ThreadReference(
    INOUT   PTHREAD                 Thread
    )
{
    ASSERT( NULL != Thread );

    RfcReference(&Thread->RefCnt);
}

static
void
_ThreadDereference(
    INOUT   PTHREAD                 Thread
    )
{
    ASSERT( NULL != Thread );

    RfcDereference(&Thread->RefCnt);
}

static
void
_ThreadDestroy(
    IN      PVOID                   Object,
    IN_OPT  PVOID                   Context
    )
{
    INTR_STATE oldState;
    PTHREAD pThread = (PTHREAD) CONTAINING_RECORD(Object, THREAD, RefCnt);

    ASSERT(NULL != pThread);
    ASSERT(NULL == Context);

    LockAcquire(&m_threadSystemData.AllThreadsLock, &oldState);
    RemoveEntryList(&pThread->AllList);
    LockRelease(&m_threadSystemData.AllThreadsLock, oldState);

    // This must be done before removing the thread from the process list, else
    // this may be the last thread and the process VAS will be freed by the time
    // ProcessRemoveThreadFromList - this function also dereferences the process
    if (NULL != pThread->UserStack)
    {
        // Free UM stack
        MmuFreeStack(pThread->UserStack, pThread->Process);
        pThread->UserStack = NULL;
    }

    ProcessRemoveThreadFromList(pThread);

    if (NULL != pThread->Name)
    {
        ExFreePoolWithTag(pThread->Name, HEAP_THREAD_TAG);
        pThread->Name = NULL;
    }

    if (NULL != pThread->Stack)
    {
        // This is the kernel mode stack
        // It does not 'belong' to any process => pass NULL
        MmuFreeStack(pThread->Stack, NULL);
        pThread->Stack = NULL;
    }

    ExFreePoolWithTag(pThread, HEAP_THREAD_TAG);
}

static
void
_ThreadKernelFunction(
    IN      PFUNC_ThreadStart       Function,
    IN_OPT  PVOID                   Context
    )
{
    STATUS exitStatus;

    ASSERT(NULL != Function);

    CHECK_STACK_ALIGNMENT;

    ASSERT(CpuIntrGetState() == INTR_ON);
    exitStatus = Function(Context);

    ThreadExit(exitStatus);
    NOT_REACHED;
}

INT64
_ThreadComparePriorityReadyList(
    IN      PLIST_ENTRY             e1,
    IN      PLIST_ENTRY             e2,
    IN_OPT  PVOID                   Context
)
{
    UNREFERENCED_PARAMETER(Context);
    PTHREAD pTh1;
    PTHREAD pTh2;

    THREAD_PRIORITY prio2;
    THREAD_PRIORITY prio1;

    pTh1 = CONTAINING_RECORD(e1, THREAD, ReadyList);
    pTh2 = CONTAINING_RECORD(e2, THREAD, ReadyList);

    prio2 = ThreadGetPriority(pTh2);
    prio1 = ThreadGetPriority(pTh1);

    if (prio2 < prio1) {
        return -1;
    }
    else {
        if (prio2 > prio1) {
            return  1;
        }
        else {
            return 0;
        }
    }
}
}

void ThreadDonatePriority(IN PTHREAD thr, IN PTHREAD trmut) {

    PTHREAD crtTrmut = trmut;
    while (crtTrmut != NULL) {

        if (thr->Priority > crtTrmut->Priority)
        {
            crtTrmut->Priority = thr->Priority;
        }

        if (crtTrmut->WaitedMutex != NULL) {
            crtTrmut = crtTrmut->WaitedMutex->Holder;
        }
        else {
            crtTrmut = NULL;
        }

    }

}

void ThreadRecomputePriority(IN PTHREAD thr) {

    THREAD_PRIORITY thrPriority = thr->RealPriority;

    for (DWORD i = 0; i < ListSize(&thr->AcquiredMutexesList); i = i + 1) {
        PLIST_ENTRY pmut = GetListElemByIndex(&thr->AcquiredMutexesList, i);
        PMUTEX mut = CONTAINING_RECORD(pmut, MUTEX, AcquiredMutexListElem);

        for (DWORD j = 0; j < ListSize(&mut->WaitingList); j = j + 1) {
            PLIST_ENTRY ptr = GetListElemByIndex(&mut->WaitingList, j);
            PTHREAD tr = CONTAINING_RECORD(ptr, THREAD, ReadyList);
            if (tr->Priority > thrPriority) {
                thrPriority = tr->Priority;
            }
        }
    }

    thr->Priority = thrPriority;

}