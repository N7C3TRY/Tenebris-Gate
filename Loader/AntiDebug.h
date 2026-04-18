#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <windows.h>

BOOL IsDebuggerPresentPeb(void);
BOOL IsRemoteDebuggerAttached(void);
BOOL IsHardwareBreakpointSet(void);
BOOL CanOpenCsrss(void);
void SandboxDelayPrimeCounting(DWORD dwSeconds);

BOOL RunAntiDebugChecks(void);

#endif /* ANTI_DEBUG_H */
