#include "SelfDestruct.h"
#include "Config.h"
#include <winternl.h>

typedef struct _MY_FILE_RENAME_INFO {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    DWORD   FileNameLength;
    WCHAR   FileName[256];
} MY_FILE_RENAME_INFO;

typedef struct _MY_FILE_DISPOSITION_INFO {
    BOOLEAN DeleteFile;
} MY_FILE_DISPOSITION_INFO;

BOOL SelfDestructFromDisk(void) {
    WCHAR wszPath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(NULL, wszPath, MAX_PATH))
        return FALSE;

    DBG_STEP("Self-destruct: wiping %ls", wszPath);

    /*
     * Step 1: Open the running executable with DELETE permission.
     * Rename the default $DATA stream to an ADS (:x), effectively
     * making the main file content 0 bytes on disk.
     */
    HANDLE hFile = CreateFileW(
        wszPath, DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        DBG_FAIL("Self-destruct: cannot open self (err=%lu)", GetLastError());
        return FALSE;
    }

    MY_FILE_RENAME_INFO renameInfo = { 0 };
    WCHAR wszStream[] = L":x";
    renameInfo.ReplaceIfExists = FALSE;
    renameInfo.RootDirectory   = NULL;
    renameInfo.FileNameLength  = (DWORD)(wcslen(wszStream) * sizeof(WCHAR));
    memcpy(renameInfo.FileName, wszStream, renameInfo.FileNameLength);

    BOOL bRenamed = SetFileInformationByHandle(
        hFile, FileRenameInfo,
        &renameInfo,
        sizeof(renameInfo)
    );
    CloseHandle(hFile);

    if (!bRenamed) {
        DBG_FAIL("Self-destruct: stream rename failed (err=%lu)", GetLastError());
        return FALSE;
    }
    DBG_OK("Self-destruct: file stream renamed (content now 0 bytes on disk)");

    /*
     * Step 2: Reopen the (now contentless) file and mark for deletion.
     * When the last handle closes (process exit), the file entry is removed.
     */
    hFile = CreateFileW(
        wszPath, DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        DBG_FAIL("Self-destruct: cannot reopen for delete (err=%lu)", GetLastError());
        return FALSE;
    }

    MY_FILE_DISPOSITION_INFO dispInfo = { TRUE };
    BOOL bMarked = SetFileInformationByHandle(
        hFile, FileDispositionInfo,
        &dispInfo,
        sizeof(dispInfo)
    );
    CloseHandle(hFile);

    if (!bMarked) {
        DBG_FAIL("Self-destruct: delete mark failed (err=%lu)", GetLastError());
        return FALSE;
    }
    DBG_OK("Self-destruct: file marked for deletion -- will vanish on process exit");

    return TRUE;
}
