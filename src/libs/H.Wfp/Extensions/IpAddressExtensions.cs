using System.Net;

namespace H.Wfp.Extensions;

public static class IpAddressExtensions
{
    public static uint ToInteger(this IPAddress address)
    {
        address = address ?? throw new ArgumentNullException(nameof(address));

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

    // internal static FWP_BYTE_ARRAY16 ToArray16(this IPAddress address)
    // {
    //     var bytes = address.GetAddressBytes();
    //
    //     return new FWP_BYTE_ARRAY16
    //     {
    //         byteArray16 = new FWP_BYTE_ARRAY16.__byte_16
    //         {
    //             _0 = bytes[0],
    //             _1 = bytes[1],
    //             _2 = bytes[2],
    //             _3 = bytes[3],
    //             _4 = bytes[4],
    //             _5 = bytes[5],
    //             _6 = bytes[6],
    //             _7 = bytes[7],
    //             _8 = bytes[8],
    //             _9 = bytes[9],
    //             _10 = bytes[10],
    //             _11 = bytes[11],
    //             _12 = bytes[12],
    //             _13 = bytes[13],
    //             _14 = bytes[14],
    //             _15 = bytes[15],
    //         }
    //     };
    // }
}
