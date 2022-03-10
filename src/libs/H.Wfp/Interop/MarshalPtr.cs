using System.Runtime.InteropServices;

namespace H.Wfp.Interop;

public class MarshalPtr<T> : IDisposable
{
    #region Properties

    public T Value { get; }
    public IntPtrWrapper IntPtrWrapper { get; }

    #endregion

    #region Constructors

    public MarshalPtr(T value, int size, Action<IntPtrWrapper> initializeAction)
    {
        Value = value;
        IntPtrWrapper = new IntPtrWrapper(
            Marshal.AllocHGlobal(size),
            Marshal.FreeHGlobal);

        initializeAction?.Invoke(IntPtrWrapper);
    }

    #endregion

    #region Methods

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            IntPtrWrapper.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public static implicit operator IntPtr(MarshalPtr<T> guidPtr)
    {
        return guidPtr.IntPtrWrapper;
    }

    #endregion
}
