using System.Runtime.Versioning;
using System.Security;

namespace H.Wfp.Interop;

[SecurityCritical]
[SupportedOSPlatform("windows6.0.6000")]
public sealed unsafe class SafeFwpmHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeFwpmHandle()
        : base(ownsHandle: true)
    {
    }

    internal SafeFwpmHandle(IntPtr preexistingHandle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(preexistingHandle);
    }

    [SecurityCritical]
    protected override bool ReleaseHandle()
    {
        var pointer = handle.ToPointer();
        PInvoke.FwpmFreeMemory0(&pointer);
        
        return true;
    }
}