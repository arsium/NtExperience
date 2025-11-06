/// <summary>
/// Fully reversed RtlAdjustPrivilege with some improvements.
/// With thread impersonation, privilege cannot be seen with ProcessHacker or ProcMon.
/// </summary>
/// <param name="privilege"></param>
/// <param name="withThread"></param>
/// <returns></returns>
FORCEINLINE NTSTATUS C AdjustPrivilege(DWORD privilege, BOOLEAN withThread)
{
    HANDLE token = NULL;
    NTSTATUS n = STATUS_SUCCESS;

    if (!withThread)
    {
        PNtOpenProcessToken ntOpenProcessToken = GetProcedureAddressNt("NtOpenProcessToken\0");
        n = ntOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token);
    }
    else
    {
        SECURITY_QUALITY_OF_SERVICE securityService;
        securityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        securityService.ImpersonationLevel = SecurityImpersonation;
        securityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        securityService.EffectiveOnly = FALSE;

        PNtImpersonateThread pImpersonateThread = GetProcedureAddressNt("NtImpersonateThread\0");

        n = pImpersonateThread(
            NtCurrentThread(),
            NtCurrentThread(),
            &securityService
        );

        //printf("pImpersonateThread : %x\n", n);
        if (n != STATUS_SUCCESS)
            return n;

        PNtOpenThreadToken ntOpenThreadToken = GetProcedureAddressNt("NtOpenThreadToken\0");
        n = ntOpenThreadToken(NtCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &token);//0x28
        //printf("ntOpenThreadToken : %x\n", n);
    }

    if (n != STATUS_SUCCESS)
        return n;

    PNtAdjustPrivilegesToken ntAdjustToken = GetProcedureAddressNt("NtAdjustPrivilegesToken\0");
    TOKEN_PRIVILEGES newState;
    newState.Privileges[0].Luid.LowPart = privilege;
    newState.PrivilegeCount = 0x1;
    newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    TOKEN_PRIVILEGES oldState;
    ULONG length = 0;
    n = ntAdjustToken(token, FALSE, &newState, sizeof(TOKEN_PRIVILEGES), &oldState, &length);
    //printf("ntAdjustToken : %x\n", n);
    return n;
}
/// <summary>
/// Fully reversed RtlAcquirePrivilege
/// With thread impersonation, privilege cannot be seen with ProcessHacker or ProcMon.
/// </summary>
/// <param name="privilege"></param>
/// <param name="withThread"></param>
/// <returns></returns>
NOINLINE NTSTATUS C AcquirePrivilege(DWORD privilege, BOOLEAN withThread)
{
    HANDLE token = NULL;
    NTSTATUS n = STATUS_SUCCESS;

    if (!withThread)
    {
        PNtOpenProcessTokenEx pNtOpenTokenEx = GetProcedureAddressNt("NtOpenProcessTokenEx\0");
        n = pNtOpenTokenEx(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, 0x200, &token);
        //printf("pNtOpenTokenEx : %x\n", n);
        if (n != STATUS_SUCCESS)
            return n;

        PNtAdjustPrivilegesToken ntAdjustToken = GetProcedureAddressNt("NtAdjustPrivilegesToken\0");
        TOKEN_PRIVILEGES newState;
        newState.Privileges[0].Luid.LowPart = privilege;
        newState.PrivilegeCount = 0x1;
        newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        TOKEN_PRIVILEGES oldState;
        ULONG length = 0;
        n = ntAdjustToken(token, FALSE, &newState, 0x400, &oldState, &length);

        //printf("ntAdjustToken : %x\n", n);
        return n;
    }
    else
    {
        PNtOpenProcessTokenEx pNtOpenTokenEx = GetProcedureAddressNt("NtOpenProcessTokenEx\0");
        n = pNtOpenTokenEx(NtCurrentProcess(), TOKEN_DUPLICATE, 0x200, &token);
        //printf("pNtOpenTokenEx : %x\n", n);
        if (n != STATUS_SUCCESS)
            return n;


        PNtDuplicateToken pDuplicateToken = GetProcedureAddressNt("NtDuplicateToken\0");
        HANDLE duplicateToken = (HANDLE)NULL;
        OBJECT_ATTRIBUTES objectAtt;

        SECURITY_QUALITY_OF_SERVICE securityService;
        securityService.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        securityService.ImpersonationLevel = SecurityImpersonation;
        securityService.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
        securityService.EffectiveOnly = FALSE;

        objectAtt.Length = sizeof(struct _OBJECT_ATTRIBUTES);
        objectAtt.RootDirectory = NULL;
        objectAtt.Attributes = 0;
        objectAtt.ObjectName = NULL;
        objectAtt.SecurityDescriptor = NULL;
        objectAtt.SecurityQualityOfService = NULL;
        objectAtt.SecurityQualityOfService = &securityService;
        /*
        _OBJECT_ATTRIBUTES
        Aligned on 8 bytes (48)
                          Length                    RootDirectory
        00000001EC8FF990  30 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
                          ObjectName                Attributes ???? Always same value ??
        00000001EC8FF9A0  00 00 00 00 00 00 00 00 | 00 02 00 00 | ?? FF 7F 00 00
                          SecurityDescriptor        SecurityQualityOfService
        00000001EC8FF9B0  00 00 00 00 00 00 00 00 | C0 F9 8F EC 01 00 00 00

        _SECURITY_QUALITY_OF_SERVICE
        Aligned on 4 bytes (12)
                          Length        ImpersonationLevel    ContextTrackingMode      EffectiveOnly
        00000001EC8FF9C0  0C 00 00 00 | 03 00 00 00         | 01                    |  00               | A1 2C

        */
        n = pDuplicateToken(token, 0x2C, &objectAtt, FALSE, TokenImpersonation, &duplicateToken);
        //printf("pDuplicateToken : %x\n", n);
        if (n != STATUS_SUCCESS)
            return n;


        PNtSetInformationThread pSetThread = GetProcedureAddressNt("NtSetInformationThread\0");
        n = pSetThread(NtCurrentThread(), ThreadImpersonationToken, (PVOID)&duplicateToken, sizeof(PVOID));

        //printf("pSetThread : %x\n", n);
        if (n != STATUS_SUCCESS)
            return n;

        PNtAdjustPrivilegesToken ntAdjustToken = GetProcedureAddressNt("NtAdjustPrivilegesToken\0");
        TOKEN_PRIVILEGES newState;
        newState.Privileges[0].Luid.LowPart = privilege;
        newState.PrivilegeCount = 0x1;
        newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        TOKEN_PRIVILEGES oldState;
        ULONG length = 0;
        n = ntAdjustToken(duplicateToken, FALSE, &newState, 0x400, &oldState, &length);

        // printf("ntAdjustToken : %x\n", n);
        return n;

    }
    return n;
}