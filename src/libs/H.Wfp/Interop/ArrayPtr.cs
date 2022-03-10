using System.Runtime.InteropServices;

namespace H.Wfp.Interop;

public class ArrayPtr<T> : IDisposable
{
    #region Properties

    public T[]? Values { get; }
    public IntPtrWrapper IntPtrWrapper { get; }

    #endregion

    #region Constructors

    public ArrayPtr(T[]? values)
    {
        Values = values;
        if (values == null || values.Length == 0)
        {
            IntPtrWrapper = new IntPtrWrapper();
            return;
        }

        IntPtrWrapper = new IntPtrWrapper(
            Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)) * values.Length),
            Marshal.FreeHGlobal);

        var longPtr = IntPtrWrapper.IntPtr.ToInt64();
        for (var i = 0; i < values.Length; i++)
        {
            var offsetPtr = new IntPtr(longPtr + i * Marshal.SizeOf(typeof(T)));

            Marshal.StructureToPtr(values[i], offsetPtr, true);
        }
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

    public static implicit operator IntPtr(ArrayPtr<T> ptr)
    {
        return ptr.IntPtrWrapper.IntPtr;
    }

    #endregion
}
