/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvmxhv.c

Abstract:

    This module implements the Simple Hyper Visor itself.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Hypervisor mode only, IRQL MAX_IRQL

--*/

#include "shv.h"
#include "vmx.h"

DECLSPEC_NORETURN
VOID
ShvVmxResume (
    VOID
    )
{
    //
    // Issue a VMXRESUME. The reason that we've defined an entire function for
    // this sole instruction is both so that we can use it as the target of the
    // VMCS when re-entering the VM After a VM-Exit, as well as so that we can
    // decorate it with the DECLSPEC_NORETURN marker, which is not set on the
    // intrinsic (as it can fail in case of an error).
    //
    __vmx_vmresume();
}

uintptr_t
FORCEINLINE
ShvVmxRead (
    _In_ UINT32 VmcsFieldId
    )
{
    size_t FieldData;

    //
    // Because VMXREAD returns an error code, and not the data, it is painful
    // to use in most circumstances. This simple function simplifies it use.
    //
    __vmx_vmread(VmcsFieldId, &FieldData);
    return FieldData;
}

INT32
ShvVmxLaunch (
    VOID
    )
{
    INT32 failureCode;

    //
    // Launch the VMCS
    //
    __vmx_vmlaunch();

    //
    // If we got here, either VMCS setup failed in some way, or the launch
    // did not proceed as planned.
    //
    failureCode = (INT32)ShvVmxRead(VM_INSTRUCTION_ERROR);
    __vmx_off();

    //
    // Return the error back to the caller
    //
    return failureCode;
}

VOID
ShvVmxHandleInvd (
    VOID
    )
{
    //
    // This is the handler for the INVD instruction. Technically it may be more
    // correct to use __invd instead of __wbinvd, but that intrinsic doesn't
    // actually exist. Additionally, the Windows kernel (or HAL) don't contain
    // any example of INVD actually ever being used. Finally, Hyper-V itself
    // handles INVD by issuing WBINVD as well, so we'll just do that here too.
    //
    __wbinvd();
}

VOID
ShvVmxHandleCpuid (
    _In_ PSHV_VP_STATE VpState
    )
{
    INT32 cpu_info[4];

    //
    // Check for the magic CPUID sequence, and check that it is is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point.
    //
    if ((VpState->VpRegs->Rax == 0x41414141) &&
        (VpState->VpRegs->Rcx == 0x42424242) &&
        ((ShvVmxRead(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM))
    {
        VpState->ExitVm = TRUE;
        return;
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs.
    //
    __cpuidex(cpu_info, (INT32)VpState->VpRegs->Rax, (INT32)VpState->VpRegs->Rcx);

	switch (VpState->VpRegs->Rax)
	{
	case 1:
		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
		break;
	case HYPERV_CPUID_INTERFACE:
		// Return our interface identifier
		cpu_info[0] = ' vhS';
		break;
	default:
		break;
	}

    // Copy the values from the logical processor registers into the VP GPRs.
    VpState->VpRegs->Rax = cpu_info[0];
    VpState->VpRegs->Rbx = cpu_info[1];
    VpState->VpRegs->Rcx = cpu_info[2];
    VpState->VpRegs->Rdx = cpu_info[3];
}

VOID
ShvVmxHandleXsetbv (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // Simply issue the XSETBV instruction on the native logical processor.
    //

    _xsetbv((UINT32)VpState->VpRegs->Rcx,
            VpState->VpRegs->Rdx << 32 |
            VpState->VpRegs->Rax);
}

VOID
ShvVmxHandleVmx (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // Set the CF flag, which is how VMX instructions indicate failure
    //
    VpState->GuestEFlags |= 0x1; // VM_FAIL_INVALID

    //
    // RFLAGs is actually restored from the VMCS, so update it here
    //
    __vmx_vmwrite(GUEST_RFLAGS, VpState->GuestEFlags);
}

VOID
ShvVmxHandleCrAccess(
	_In_ PSHV_VP_STATE VpState
)
{
	MOV_CR_QUALIFICATION tExitQualification = { 0 };
	PULONG_PTR pulReg = NULL;
	UINT32 dwCr = 0;
	
	__vmx_vmread(EXIT_QUALIFICATION, &tExitQualification.all);
	pulReg = ShvVmxSelectRegister(tExitQualification.fields.gp_register, VpState);
	// NT_ASSERT(NULL != pulReg);

	switch (tExitQualification.fields.access_type)
	{
	case MOV_CR_ACCESS_TYPE_TO_CR:
		switch (tExitQualification.fields.control_register)
		{
		case 0:
			dwCr = (UINT32)(*pulReg);
			ShvVmxAdjustCr0(&dwCr);
			__vmx_vmwrite(GUEST_CR0, dwCr);
			__vmx_vmwrite(CR0_READ_SHADOW, dwCr);
			break;
		case 3:
			// TODO: Do INVVPID and EPT page-table change
			__vmx_vmwrite(GUEST_CR3, *pulReg);
			break;
		case 4:
			dwCr = (UINT32)(*pulReg);
			ShvVmxAdjustCr4(&dwCr);
			__vmx_vmwrite(GUEST_CR4, dwCr);
			__vmx_vmwrite(CR4_READ_SHADOW, dwCr);
			break;
		case 8:
			__writecr8(*pulReg);
			break;
		default:
			// NT_ASSERT(FALSE);
			ShvOsDebugPrint("MOV to CR bad control register index %d",
				tExitQualification.fields.control_register);
			VpState->ExitVm = TRUE;
		}
		break;
	case MOV_CR_ACCESS_TYPE_FROM_CR:
		switch (tExitQualification.fields.control_register)
		{
		case 0:
			__vmx_vmread(CR0_READ_SHADOW, pulReg);
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, pulReg);
			break;
		case 4:
			__vmx_vmread(CR4_READ_SHADOW, pulReg);
			break;
		case 8:
			*pulReg = __readcr8();
			break;
		default:
			// NT_ASSERT(FALSE);
			ShvOsDebugPrint("MOV from CR bad control register index %d",
				tExitQualification.fields.control_register);
			VpState->ExitVm = TRUE;
		}
		break;
	default:
		// NT_ASSERT(FALSE); // unimplemented
		ShvOsDebugPrint("Unimplemented CR access %d",
			tExitQualification.fields.access_type);
		VpState->ExitVm = TRUE;
		break;
	}
}

//
// Handle RDMSR opcode - will only be called if we're not using the MSR bitmap
//
VOID
ShvVmxHandleRdmsr(
	_In_ PSHV_VP_STATE VpState
)
{
	LARGE_INTEGER qwMsrValue = {0};
	qwMsrValue.QuadPart = (UINT64)__readmsr((UINT32)VpState->VpRegs->Rcx);
	VpState->VpRegs->Rdx = qwMsrValue.HighPart;
	VpState->VpRegs->Rax = qwMsrValue.LowPart;
}

//
// Handle WRMSR opcode - will only be called if we're not using the MSR bitmap
//
VOID
ShvVmxHandleWrmsr(
	_In_ PSHV_VP_STATE VpState
)
{
	LARGE_INTEGER qwMsrValue = {0};
	qwMsrValue.HighPart	= (UINT32)VpState->VpRegs->Rdx;
	qwMsrValue.LowPart	= (UINT32)VpState->VpRegs->Rax;
	__writemsr((UINT32)VpState->VpRegs->Rcx, qwMsrValue.QuadPart);

	// TODO: DELETE ME
	// __writemsr(0x176, 0xDEADBEEF);
}

VOID
ShvVmxHandleExit (
    _In_ PSHV_VP_STATE VpState
    )
{
	//
    // This is the generic VM-Exit handler. Decode the reason for the exit and
    // call the appropriate handler. As per Intel specifications, given that we
    // have requested no optional exits whatsoever, we should only see CPUID,
    // INVD, XSETBV and other VMX instructions. GETSEC cannot happen as we do
    // not run in SMX context.
    //

	// TODO: DELETE ME
	// __writemsr(0x176, 0xDEADBABE);

	if ((VpState->ExitReason != EXIT_REASON_CPUID) &&
		(VpState->ExitReason != EXIT_REASON_MSR_READ)) {
		UINT64 qwValue = __readmsr(0x176);
		__writemsr(0x176, qwValue);
	}

    switch (VpState->ExitReason)
    {
    case EXIT_REASON_CPUID:
        ShvVmxHandleCpuid(VpState);
        break;
    case EXIT_REASON_INVD:
        ShvVmxHandleInvd();
        break;
    case EXIT_REASON_XSETBV:
        ShvVmxHandleXsetbv(VpState);
        break;
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        ShvVmxHandleVmx(VpState);
        break;

	case EXIT_REASON_CR_ACCESS:
		ShvVmxHandleCrAccess(VpState);
		break;

	// TODO: DELETE ME
	case EXIT_REASON_MSR_READ:
		ShvVmxHandleRdmsr(VpState);
		break;

	// TODO: DELETE ME
	case EXIT_REASON_MSR_WRITE:
		ShvVmxHandleWrmsr(VpState);
		break;

	// TODO: DELETE ME
	case EXIT_REASON_TRIPLE_FAULT:
		// ShvOsDebugPrint("Triple Fault at 0x%016x", VpState->GuestRip);
		// RUNTIME_DEBUGBREAK();
		break;

    default:
		// ShvOsDebugPrint("Unimplemented VM-Exit %d", VpState->ExitReason);
		RUNTIME_DEBUGBREAK();
        break;
    }

	// Skip the emulated opcode - only if it's really emulated
	// TODO:	This might be redundant if VM_EXIT_INSTRUCTION_LEN is 0 
	//			on non-opcode cause VM-Exits
	if (ShvVmxShouldEmulateOpcode(VpState->ExitReason))
	{
		//
		// Move the instruction pointer to the next instruction after the one that
		// caused the exit. Since we are not doing any special handling or changing
		// of execution, this can be done for any exit reason.
		//
		VpState->GuestRip += ShvVmxRead(VM_EXIT_INSTRUCTION_LEN);
		__vmx_vmwrite(GUEST_RIP, VpState->GuestRip);
	}
}

DECLSPEC_NORETURN
VOID
ShvVmxEntryHandler (
    _In_ PCONTEXT Context
    )
{
    SHV_VP_STATE guestContext;
    PSHV_VP_DATA vpData;

    //
    // Because we had to use RCX when calling ShvOsCaptureContext, its value
    // was actually pushed on the stack right before the call. Go dig into the
    // stack to find it, and overwrite the bogus value that's there now.
    //
    Context->Rcx = *(UINT64*)((uintptr_t)Context - sizeof(Context->Rcx));

    //
    // Get the per-VP data for this processor.
    //
    vpData = (VOID*)((uintptr_t)(Context + 1) - KERNEL_STACK_SIZE);

    //
    // Build a little stack context to make it easier to keep track of certain
    // guest state, such as the RIP/RSP/RFLAGS, and the exit reason. The rest
    // of the general purpose registers come from the context structure that we
    // captured on our own with RtlCaptureContext in the assembly entrypoint.
    //
    guestContext.GuestEFlags = ShvVmxRead(GUEST_RFLAGS);
    guestContext.GuestRip = ShvVmxRead(GUEST_RIP);
    guestContext.GuestRsp = ShvVmxRead(GUEST_RSP);
    guestContext.ExitReason = ShvVmxRead(VM_EXIT_REASON) & 0xFFFF;
    guestContext.VpRegs = Context;
    guestContext.ExitVm = FALSE;

    //
    // Call the generic handler
    //
    ShvVmxHandleExit(&guestContext);

    //
    // Did we hit the magic exit sequence, or should we resume back to the VM
    // context?
    //
    if (guestContext.ExitVm != FALSE)
    {
        //
        // Return the VP Data structure in RAX:RBX which is going to be part of
        // the CPUID response that the caller (ShvVpUninitialize) expects back.
        // Return confirmation in RCX that we are loaded
        //
        Context->Rax = (uintptr_t)vpData >> 32;
        Context->Rbx = (uintptr_t)vpData & 0xFFFFFFFF;
        Context->Rcx = 0x43434343;

        //
        // Perform any OS-specific CPU uninitialization work
        //
        ShvOsUnprepareProcessor(vpData);

        //
        // Our callback routine may have interrupted an arbitrary user process,
        // and therefore not a thread running with a system wide page directory.
        // Therefore if we return back to the original caller after turning off
        // VMX, it will keep our current "host" CR3 value which we set on entry
        // to the PML4 of the SYSTEM process. We want to return back with the
        // correct value of the "guest" CR3, so that the currently executing
        // process continues to run with its expected address space mappings.
        //
        __writecr3(ShvVmxRead(GUEST_CR3));

        //
        // Finally, restore the stack, instruction pointer and EFLAGS to the
        // original values present when the instruction causing our VM-Exit
        // execute (such as ShvVpUninitialize). This will effectively act as
        // a longjmp back to that location.
        //
        Context->Rsp = guestContext.GuestRsp;
        Context->Rip = (UINT64)guestContext.GuestRip;
        Context->EFlags = (UINT32)guestContext.GuestEFlags;

        //
        // Turn off VMX root mode on this logical processor. We're done here.
        //
        __vmx_off();
    }
    else
    {
        //
        // Because we won't be returning back into assembly code, nothing will
        // ever know about the "pop rcx" that must technically be done (or more
        // accurately "add rsp, 4" as rcx will already be correct thanks to the
        // fixup earlier. In order to keep the stack sane, do that adjustment
        // here.
        //
        Context->Rsp += sizeof(Context->Rcx);

        //
        // Return into a VMXRESUME intrinsic, which we broke out as its own
        // function, in order to allow this to work. No assembly code will be
        // needed as RtlRestoreContext will fix all the GPRs, and what we just
        // did to RSP will take care of the rest.
        //
        Context->Rip = (UINT64)ShvVmxResume;
    }

    //
    // Restore the context to either ShvVmxResume, in which case the CPU's VMX
    // facility will do the "true" return back to the VM (but without restoring
    // GPRs, which is why we must do it here), or to the original guest's RIP,
    // which we use in case an exit was requested. In this case VMX must now be
    // off, and this will look like a longjmp to the original stack and RIP.
    //
    ShvOsRestoreContext(Context);
}

