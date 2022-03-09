using System.Net;
using System.Net.Sockets;

namespace H.OpenVpn.Utilities;

internal static class NetworkUtilities
{
    #region Methods

    public static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    #endregion
}
