using System.Net;
using System.Net.Sockets;

namespace H.OpenVpn.Utilities;

public class TcpClientWrapper : IDisposable
{
    #region Properties

    public TcpClient TcpClient { get; }
    private TimeSpan Timeout { get; }

    #endregion

    #region Constructors

    public TcpClientWrapper(TcpClient client, TimeSpan timeout)
    {
        TcpClient = client;
        Timeout = timeout;
    }

    public TcpClientWrapper(TimeSpan timeout) : this(new TcpClient
    {
        ReceiveTimeout = (int)timeout.TotalMilliseconds,
        SendTimeout = (int)timeout.TotalMilliseconds
    }, timeout)
    {
    }

    #endregion

    #region Public methods

    public void Connect(IPAddress address, int port)
    {
        var result = TcpClient.BeginConnect(address, port, null, null);
        {
            using (var handle = result.AsyncWaitHandle) {
                if (!result.AsyncWaitHandle.WaitOne(Timeout, false))
                {
                    throw new TimeoutException();
                }
            }

            TcpClient.EndConnect(result);
        }

        if (!TcpClient.Connected)
        {
            throw new TimeoutException();
        }
    }

    public void Dispose()
    {
        TcpClient.Close();
        GC.SuppressFinalize(this);
    }

    #endregion
}
