using System.Net;

namespace H.Wfp.Extensions;

public static class IpAddressExtensions
{
    public static uint ToInteger(this IPAddress address)
    {
        var bytes = address.GetAddressBytes();

        // flip big-endian(network order) to little-endian
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    public static IPAddress ToIpAddress(this long address)
    {
        return new IPAddress(address);
    }
}
