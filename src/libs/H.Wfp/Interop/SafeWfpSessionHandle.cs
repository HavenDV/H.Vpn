using System.Security;

namespace H.Wfp.Interop;

[SecurityCritical]
public sealed class SafeWfpSessionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWfpSessionHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeWfpSessionHandle(IntPtr preexistingHandle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(preexistingHandle);
    }

    [SecurityCritical]
    protected override bool ReleaseHandle()
    {
        var result = PInvoke.FwpmEngineClose0(new HANDLE(handle));
        
        return result == 0;
    }
}