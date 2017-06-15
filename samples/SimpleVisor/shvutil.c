/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvutil.c

Abstract:

    This module implements utility functions for the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#include "shv.h"

// TRUE if the VM-Exit reason given is of an opcode, else, FALSE
const BOOLEAN abVmExitEmulatesOpcode[EXIT_REASONS_MAX] = {
	FALSE, // EXIT_REASON_EXCEPTION_NMI = 0,
	FALSE, // EXIT_REASON_EXTERNAL_INTERRUPT = 1,
	FALSE, // EXIT_REASON_TRIPLE_FAULT = 2,
	FALSE, // EXIT_REASON_INIT = 3,
	FALSE, // EXIT_REASON_SIPI = 4,
	FALSE, // EXIT_REASON_IO_SMI = 5,
	FALSE, // EXIT_REASON_OTHER_SMI = 6,
	FALSE, // EXIT_REASON_PENDING_VIRT_INTR = 7,
	FALSE, // EXIT_REASON_PENDING_VIRT_NMI = 8,
	FALSE, // EXIT_REASON_TASK_SWITCH = 9,
	TRUE, // EXIT_REASON_CPUID = 10,
	TRUE, // EXIT_REASON_GETSEC = 11,
	TRUE, // EXIT_REASON_HLT = 12,
	TRUE, // EXIT_REASON_INVD = 13,
	TRUE, // EXIT_REASON_INVLPG = 14,
	TRUE, // EXIT_REASON_RDPMC = 15,
	TRUE, // EXIT_REASON_RDTSC = 16,
	TRUE, // EXIT_REASON_RSM = 17,
	TRUE, // EXIT_REASON_VMCALL = 18,
	TRUE, // EXIT_REASON_VMCLEAR = 19,
	TRUE, // EXIT_REASON_VMLAUNCH = 20,
	TRUE, // EXIT_REASON_VMPTRLD = 21,
	TRUE, // EXIT_REASON_VMPTRST = 22,
	TRUE, // EXIT_REASON_VMREAD = 23,
	TRUE, // EXIT_REASON_VMRESUME = 24,
	TRUE, // EXIT_REASON_VMWRITE = 25,
	TRUE, // EXIT_REASON_VMXOFF = 26,
	TRUE, // EXIT_REASON_VMXON = 27,
	TRUE, // EXIT_REASON_CR_ACCESS = 28,
	TRUE, // EXIT_REASON_DR_ACCESS = 29,
	TRUE, // EXIT_REASON_IO_INSTRUCTION = 30,
	TRUE, // EXIT_REASON_MSR_READ = 31,
	TRUE, // EXIT_REASON_MSR_WRITE = 32,
	FALSE, // EXIT_REASON_INVALID_GUEST_STATE = 33,
	FALSE, // EXIT_REASON_MSR_LOADING = 34,
	TRUE, // EXIT_REASON_MWAIT_INSTRUCTION = 36,
	FALSE, // EXIT_REASON_MONITOR_TRAP_FLAG = 37,
	TRUE, // EXIT_REASON_MONITOR_INSTRUCTION = 39,
	TRUE, // EXIT_REASON_PAUSE_INSTRUCTION = 40,
	FALSE, // EXIT_REASON_MCE_DURING_VMENTRY = 41,
	FALSE, // EXIT_REASON_TPR_BELOW_THRESHOLD = 43,
	TRUE, // EXIT_REASON_APIC_ACCESS = 44,
	TRUE, // EXIT_REASON_ACCESS_GDTR_OR_IDTR = 46,
	TRUE, // EXIT_REASON_ACCESS_LDTR_OR_TR = 47,
	FALSE, // EXIT_REASON_EPT_VIOLATION = 48,
	FALSE, // EXIT_REASON_EPT_MISCONFIG = 49,
	TRUE, // EXIT_REASON_INVEPT = 50,
	TRUE, // EXIT_REASON_RDTSCP = 51,
	FALSE, // EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 52,
	TRUE, // EXIT_REASON_INVVPID = 53,
	TRUE, // EXIT_REASON_WBINVD = 54,
	TRUE, // EXIT_REASON_XSETBV = 55,
	TRUE, // EXIT_REASON_APIC_WRITE = 56,
	TRUE, // EXIT_REASON_RDRAND = 57,
	TRUE, // EXIT_REASON_INVPCID = 58,
	TRUE, // EXIT_REASON_RDSEED = 61,
	FALSE, // EXIT_REASON_PML_FULL = 62,
	TRUE, // EXIT_REASON_XSAVES = 63,
	TRUE, // EXIT_REASON_XRSTORS = 64,
	TRUE, // EXIT_REASON_PCOMMIT = 65,
};

BOOLEAN
ShvVmxShouldEmulateOpcode (
	_In_ const UINT16 wExitReason
	)
{
	if (wExitReason > EXIT_REASONS_MAX)
	{
		return FALSE;
	}
	return abVmExitEmulatesOpcode[wExitReason];
}

VOID
ShvUtilConvertGdtEntry (
    _In_ VOID* GdtBase,
    _In_ UINT16 Selector,
    _Out_ PVMX_GDTENTRY64 VmxGdtEntry
    )
{
    PKGDTENTRY64 gdtEntry;

    //
    // Reject LDT or NULL entries
    //
    if ((Selector == 0) ||
        (Selector & SELECTOR_TABLE_INDEX) != 0)
    {
        VmxGdtEntry->Limit = VmxGdtEntry->AccessRights = 0;
        VmxGdtEntry->Base = 0;
        VmxGdtEntry->Selector = 0;
        VmxGdtEntry->Bits.Unusable = TRUE;
        return;
    }

    //
    // Read the GDT entry at the given selector, masking out the RPL bits.
    //
    gdtEntry = (PKGDTENTRY64)((uintptr_t)GdtBase + (Selector & ~RPL_MASK));

    //
    // Write the selector directly 
    //
    VmxGdtEntry->Selector = Selector;

    //
    // Use the LSL intrinsic to read the segment limit
    //
    VmxGdtEntry->Limit = __segmentlimit(Selector);

    //
    // Build the full 64-bit effective address, keeping in mind that only when
    // the System bit is unset, should this be done.
    //
    // NOTE: The Windows definition of KGDTENTRY64 is WRONG. The "System" field
    // is incorrectly defined at the position of where the AVL bit should be.
    // The actual location of the SYSTEM bit is encoded as the highest bit in
    // the "Type" field.
    //
    VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) |
                         (gdtEntry->Bytes.BaseMiddle << 16) |
                         (gdtEntry->BaseLow)) & 0xFFFFFFFF;
    VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ?
                         ((uintptr_t)gdtEntry->BaseUpper << 32) : 0;

    //
    // Load the access rights
    //
    VmxGdtEntry->AccessRights = 0;
    VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
    VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

    //
    // Finally, handle the VMX-specific bits
    //
    VmxGdtEntry->Bits.Reserved = 0;
    VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

UINT32
ShvUtilAdjustMsr (
    _In_ LARGE_INTEGER ControlValue,
    _In_ UINT32 DesiredValue
    )
{
    //
    // VMX feature/capability MSRs encode the "must be 0" bits in the high word
    // of their value, and the "must be 1" bits in the low word of their value.
    // Adjust any requested capability/feature based on these requirements.
    //
    DesiredValue &= ControlValue.HighPart;
    DesiredValue |= ControlValue.LowPart;
    return DesiredValue;
}

VOID
ShvVmxAdjustCr0 (
	_Out_ UINT32 * pdwCr0
	)
{
	LARGE_INTEGER tFixed0 = { 0 };
	LARGE_INTEGER tFixed1 = { 0 };

	// NT_ASSERT(NULL != pdwCr0);

	tFixed0.QuadPart = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	tFixed1.QuadPart = __readmsr(MSR_IA32_VMX_CR0_FIXED1);

	*pdwCr0 &= tFixed1.LowPart;
	*pdwCr0 |= tFixed0.LowPart;
}

VOID
ShvVmxAdjustCr4 (
	_Out_ UINT32 * pdwCr4
	)
{
	LARGE_INTEGER tFixed0 = { 0 };
	LARGE_INTEGER tFixed1 = { 0 };

	// NT_ASSERT(NULL != pdwCr4);

	tFixed0.QuadPart = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	tFixed1.QuadPart = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

	*pdwCr4 &= tFixed1.LowPart;
	*pdwCr4 |= tFixed0.LowPart;
}

ULONG_PTR *
ShvVmxSelectRegister (
	_In_ const ULONG_PTR ulIndex,
	_In_ PSHV_VP_STATE VpData
	)
{
	ULONG_PTR *pulRegister = NULL;
	
	// Select the register by the index in the EXIT_QUALIFICATION field
	switch (ulIndex) {
	case 0: pulRegister = &VpData->VpRegs->Rax; break;
	case 1: pulRegister = &VpData->VpRegs->Rcx; break;
	case 2: pulRegister = &VpData->VpRegs->Rdx; break;
	case 3: pulRegister = &VpData->VpRegs->Rbx; break;
	case 4: pulRegister = &VpData->VpRegs->Rsp; break;
	case 5: pulRegister = &VpData->VpRegs->Rbp; break;
	case 6: pulRegister = &VpData->VpRegs->Rsi; break;
	case 7: pulRegister = &VpData->VpRegs->Rdi; break;
	case 8: pulRegister = &VpData->VpRegs->R8; break;
	case 9: pulRegister = &VpData->VpRegs->R9; break;
	case 10: pulRegister = &VpData->VpRegs->R10; break;
	case 11: pulRegister = &VpData->VpRegs->R11; break;
	case 12: pulRegister = &VpData->VpRegs->R12; break;
	case 13: pulRegister = &VpData->VpRegs->R13; break;
	case 14: pulRegister = &VpData->VpRegs->R14; break;
	case 15: pulRegister = &VpData->VpRegs->R15; break;
	default: 
		// NT_ASSERT(FALSE);
		ShvOsDebugPrint("Bad register index %d", ulIndex);
		VpData->ExitVm = TRUE;
		break;
	}

	return pulRegister;
}
