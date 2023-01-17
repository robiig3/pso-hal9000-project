#include "HAL9000.h"
#include "ex_timer.h"
#include "iomu.h"
#include "thread_internal.h"


static struct _GLOBAL_TIMER_LIST m_globalTimerList;
static FUNC_CompareFunction _TimerCompareFunction;
static FUNC_ListFunction _ExTimerCheckFunction;

STATUS
ExTimerInit(
    OUT     PEX_TIMER       Timer,
    IN      EX_TIMER_TYPE   Type,
    IN      QWORD           Time
)
{
    STATUS status;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Type > ExTimerTypeMax)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = STATUS_SUCCESS;

    memzero(Timer, sizeof(EX_TIMER));

    Timer->Type = Type;
    if (Timer->Type != ExTimerTypeAbsolute)
    {
        // relative time

        // if the time trigger time has already passed the timer will
        // be signaled after the first scheduler tick
        Timer->TriggerTimeUs = IomuGetSystemTimeUs() + Time;
        Timer->ReloadTimeUs = Time;
    }
    else
    {
        // absolute
        Timer->TriggerTimeUs = Time;
    }

    ExEventInit(&Timer->TimerEvent, ExEventTypeNotification, FALSE);

    // add the new timer to the m_globalTimerList
    INTR_STATE oldState;

    LockAcquire(&m_globalTimerList.TimerListLock, &oldState);
    //LOG_ERROR("----- ExTimerInit here\n");

    InsertOrderedList(
        &m_globalTimerList.TimerListHead,
        &Timer->TimerListElem,
        _TimerCompareFunction,
        NULL);
    //LOG_ERROR("----- TimerCompareFunction works here\n");

    LockRelease(&m_globalTimerList.TimerListLock, oldState);

    return status;
}

void
ExTimerStart(
    IN      PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = TRUE;
}

void
ExTimerStop(
    IN      PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = FALSE;
}

void
ExTimerWait(
    INOUT   PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    if (Timer->TimerStarted) {
        ExEventWaitForSignal(&Timer->TimerEvent);
    }

}

void
ExTimerUninit(
    INOUT   PEX_TIMER       Timer
)
{
    ASSERT(Timer != NULL);

    ExTimerStop(Timer);

    Timer->TimerUninited = TRUE;

    // remove the timer from the m_globalTimerList
    INTR_STATE oldState;
    LockAcquire(&m_globalTimerList.TimerListLock, &oldState);

    PLIST_ENTRY timerEntry = ListSearchForElement(
        &m_globalTimerList.TimerListHead,
        &Timer->TimerListElem,
        FALSE,
        ExTimerCompareListElems,
        NULL
    );

    RemoveEntryList(timerEntry);

    LockRelease(&m_globalTimerList.TimerListLock, oldState);

}

INT64
ExTimerCompareTimers(
    IN      PEX_TIMER     FirstElem,
    IN      PEX_TIMER     SecondElem
)
{
    return FirstElem->TriggerTimeUs - SecondElem->TriggerTimeUs;
}

void
ExTimerSystemPreinit(void)
{
    InitializeListHead(&m_globalTimerList.TimerListHead);
    LockInit(&m_globalTimerList.TimerListLock);
}


INT64
ExTimerCompareListElems(
    IN      PLIST_ENTRY t1,
    IN      PLIST_ENTRY t2,
    IN_OPT  PVOID       context
)
{
    UNREFERENCED_PARAMETER(context);
    PEX_TIMER timer1 = CONTAINING_RECORD(t1, EX_TIMER, TimerListElem);
    PEX_TIMER timer2 = CONTAINING_RECORD(t2, EX_TIMER, TimerListElem);

    return ExTimerCompareTimers(timer1, timer2);
}


void
ExTimerCheck(INOUT PEX_TIMER timer)
{
    if (IomuGetSystemTimeUs() >= timer->TriggerTimeUs) {
        ExEventSignal(&timer->TimerEvent);
    }
}


void
ExTimerCheckAll(void)
{
    INTR_STATE oldState;

    LockAcquire(&m_globalTimerList.TimerListLock, &oldState);

    ForEachElementExecute(
        &m_globalTimerList.TimerListHead,
        &_ExTimerCheckFunction,
        NULL,
        TRUE);

    LockRelease(&m_globalTimerList.TimerListLock, oldState);
}


static
STATUS
(__cdecl _ExTimerCheckFunction) (
    IN PLIST_ENTRY   entry,
    IN_OPT PVOID context
    )
{
    UNREFERENCED_PARAMETER(context);

    PEX_TIMER timer;
    timer = CONTAINING_RECORD(entry, EX_TIMER, TimerListElem);
    if (IomuGetSystemTimeUs() >= timer->TriggerTimeUs) {
        ExEventSignal(&timer->TimerEvent);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}


static
INT64
(__cdecl _TimerCompareFunction) (
    IN      PLIST_ENTRY t1,
    IN      PLIST_ENTRY t2,
    IN_OPT  PVOID context
    )
{
    ASSERT(t1 != NULL);
    ASSERT(t2 != NULL);

    return ExTimerCompareListElems(t1, t2, context);
}