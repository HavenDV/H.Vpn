using System.Runtime.InteropServices;

namespace H.Wfp.Interop;

public class BytesPtr : MarshalPtr<byte[]>
{
    #region Constructors

    public BytesPtr(byte[] value) : base(
        value, 
        value.Length, 
        wrapper => Marshal.Copy(value, 0, wrapper, value.Length))
    {
    }

    #endregion
}
