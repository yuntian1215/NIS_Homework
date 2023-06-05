#include "privilege.h"
#include <stdio.h>

/*****************************************************
 *  请将以下函数填写完整，并实现对应的功能              *
 *    - EnableSeDebugPrivilege                       *
 *****************************************************/
 /// 推荐使用API: OpenProcessToken() LookupPrivilegeValueW() AdjustTokenPrivileges()
BOOL EnableSeDebugPrivilege() {
    //
    // ~ 30 lines of code
    // 
    HANDLE hToken;
    BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (!bRet) {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &Luid)) {
        printf("LookupPrivilegeValueW error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = Luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_SUCCESS) return TRUE;

    return FALSE;
}

/// Checks the corresponding Windows privilege and returns True or False.
BOOL CheckWindowsPrivilege(IN PWCHAR Privilege) {
    LUID luid;
    PRIVILEGE_SET privs = { 0 };
    HANDLE hProcess;
    HANDLE hToken;
    hProcess = GetCurrentProcess();
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
    if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL bResult;
    PrivilegeCheck(hToken, &privs, &bResult);
    return bResult;
}

/// 启用Administrator的SeDebugPrivilege权限
VOID AdjustProcessPrivilege() {
    BOOL success = EnableSeDebugPrivilege();
    if (!success || !CheckWindowsPrivilege((WCHAR*)SE_DEBUG_NAME)) {
        printf("AdjustProcessPrivilege() not working ...\n");
        printf("Are you running as Admin ? ...\n");
        ExitProcess(-1);
    }
    else {
        printf("\n[+] AdjustProcessPrivilege() ok .\n\n");
    }
}