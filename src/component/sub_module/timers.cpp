//
// Created by orzgg on 2021-12-01.
//

#include <gba_instance.h>

#include <task_runner.h>
#include <timers.h>

namespace gg_core::gg_io {
    Timer::Timer(GbaInstance& instance, int idx):
            _instance(instance),
            _Control((uint16_t&)instance.mmu.IOReg[0x100 + idx*4]),
            _Counter((uint16_t&)instance.mmu.IOReg[0x102 + idx*4])
    {
    }

    uint64_t Timer::GetElapsedTimeFromLastStart() {
        return _instance.GetSystemClk() - _startTimeStamp ;
    }

    Timers::Timers(GbaInstance& instance):
        _instance(instance),
        timer {
            Timer(instance, 0),
            Timer(instance, 1),
            Timer(instance, 2),
            Timer(instance, 3)
        }
    {
        // todo: reset() && stop()
        for (int i = 0 ; i < 4 ; ++i) {
            timer[ i ].overflowAction = [&](int delayedClk) {
                OnOverflow( i ) ;
                StartTimer(i, delayedClk) ;
            };
        } // for
    }

    uint16_t Timers::ReadCounter(int idx) {
        return timer[idx].ReadCounter() ;
    } // ReadCounter()

    void Timers::WriteControl(int idx, uint16_t value) {
        _instance.runner.Cancel(0) ;

        bool wasEnabled = timer[idx].IsEnabled() ;
        timer[idx]._Control = value ;

        if (idx == 0)
            timer[idx]._Control &= 0x100 ; // clear cascade bit

        if (timer[idx].IsEnabled()) {
            if (!wasEnabled)
                timer[idx].ResetCounter() ;

            if (!timer[idx].IsCascade()) {
                uint64_t late = _instance.GetSystemClk() & Timer::delayMask[ timer[idx].Prescaler() ] ;
                StartTimer(idx, late) ;
            } // if
        } // if
    } // Timers::WriteControl()

    void Timers::StartTimer(int idx, uint64_t delayed) {
        Timer& t = timer[ idx ] ;
        t._startTimeStamp = _instance.GetSystemClk() - delayed;
        uint64_t sleepClk = ((_overflowValue - t._internalCounter) << t.Prescaler()) - delayed ; // fixme: why int()?
        t.scheduledTask = _instance.runner.Schedule(sleepClk, t.overflowAction) ;
    } // StartTimer()

    void Timers::StopTimer(int idx) {
        Timer& t = timer[ idx ] ;
        t._internalCounter += t.GetElapsedTimeFromLastStart() ;

        if (t._internalCounter >= _overflowValue)
            OnOverflow(idx) ;

        _instance.runner.Cancel(t.scheduledTask->id) ;
    } // StopTimer()

    void Timers::OnOverflow(int idx) {
        using namespace gg_cpu ;
        Timer& thisTimer = timer[ idx ] ;
        thisTimer.ResetCounter() ;

        if (thisTimer.NeedIRQ()) {
            gg_cpu::IRQ_TYPE irqType = static_cast<IRQ_TYPE>(IRQ_TYPE::TIMER_0 + idx) ;
            _instance.cpu.RaiseInterrupt(irqType) ;
        } // if

        /*APU Hook here*/

        if (idx != 3) {
            Timer& nextTimer = timer[idx+ 1];
            if (nextTimer.IsEnabled() && nextTimer.IsCascade() && ++nextTimer._internalCounter == 0x10000) {
                OnOverflow(idx + 1);
            } // if
        } // if
    } // OnOverflow()
}

