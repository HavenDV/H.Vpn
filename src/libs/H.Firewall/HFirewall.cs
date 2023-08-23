using H.Wfp;
using H.Wfp.Interop;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace H.Firewall;

[SupportedOSPlatform("windows6.0.6000")]
public class HFirewall : IDisposable
{
    #region Properties

    public SafeHandle WfpSession { get; private set; } = new SafeWfpSessionHandle();
    public bool IsEnabled => !WfpSession.IsInvalid;

    #endregion

    #region Methods

    public void RunTransaction(Action<SafeHandle> action)
    {
        action = action ?? throw new ArgumentNullException(nameof(action));

        WfpSession.BeginTransaction();

        try
        {
            action.Invoke(WfpSession);
        }
        catch
        {
            WfpSession.AbortTransaction();
            throw;
        }

        WfpSession.CommitTransaction();
    }

    public void Start()
    {
        WfpSession = WfpMethods.CreateWfpSession("H.Wfp", "H.Wfp dynamic session");
    }

    public void Stop()
    {
        Dispose();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            WfpSession.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #endregion
}
