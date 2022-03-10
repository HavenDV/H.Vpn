using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace H.IpHlpApi;

public static class NetworkMethods
{
    public static void AddRoute(
        IPNetwork network,
        uint interfaceIndex, 
        ushort metric)
    {
        NativeMethods.AddRoute(
            network.Value,
            network.Netmask.ToString(), 
            "0.0.0.0", 
            interfaceIndex, 
            metric, 
            NativeMethods.MIB_IPFORWARD_TYPE.MIB_IPROUTE_TYPE_DIRECT);
    }

    public static void DeleteRoute(IPNetwork network, uint interfaceIndex)
    {
        NativeMethods.DeleteRoute(
            network.Value,
            network.Netmask.ToString(),
            "0.0.0.0",
            interfaceIndex);
    }

    public static ulong ConvertInterfaceIndexToLuid(uint index)
    {
        var result = NativeMethods.ConvertInterfaceIndexToLuid(index, out var luid);

        EnsureResultIsNull(result);

        return luid;
    }

    public static Guid ConvertInterfaceLuidToGuid(ulong luid)
    {
        var result = NativeMethods.ConvertInterfaceLuidToGuid(luid, out var guid);

        EnsureResultIsNull(result);

        return guid;
    }

    public static ulong ConvertInterfaceAliasToLuid(string alias)
    {
        var result = NativeMethods.ConvertInterfaceAliasToLuid(alias, out var luid);

        EnsureResultIsNull(result);

        return luid;
    }

    public static Tuple<uint, ushort> FindInterfaceIndexAndMetricByIp(IPAddress ip)
    {
        var routes = NativeMethods.GetRoutes(NativeMethods.FAMILY.AF_UNSPEC);

        var index = 0U;
        var metric = ushort.MaxValue;

        foreach (var route in routes.Where(route => Equals(route.Gateway, ip)))
        {
            index = route.InterfaceIndex;
            metric = Math.Min(metric, route.Metric);
        }

        return new Tuple<uint, ushort>(index, metric);
    }

    public static ulong FindTapAdapterLuid()
    {
        return ConvertInterfaceIndexToLuid(
            NativeMethods.GetAdapters(NativeMethods.FAMILY.AF_UNSPEC)
                .FirstOrDefault(adapter => adapter.Description == "TAP-Windows Adapter V9")?
                .InterfaceIndex
            ?? throw new InvalidOperationException("No available TAP adapters found"));
    }

    public static ICollection<IPAddress> GetLocalIpsV4()
    {
        return NetworkInterface
            .GetAllNetworkInterfaces()
            .Where(@interface => @interface.OperationalStatus != OperationalStatus.Down && 
                                 @interface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(@interface => @interface
                .GetIPProperties()
                .UnicastAddresses
                .Where(ip => ip.Address.AddressFamily == AddressFamily.InterNetwork &&
                             ip.IPv4Mask.ToString() == "255.255.255.0")
                .Select(ip => ip.Address))
            .ToList();
    }

    public static Guid InterfaceIndexToGuid(uint index)
    {
        var luid = ConvertInterfaceIndexToLuid(index);

        return ConvertInterfaceLuidToGuid(luid);
    }

    public static Guid InterfaceAliasToGuid(string alias)
    {
        var luid = ConvertInterfaceAliasToLuid(alias);

        return ConvertInterfaceLuidToGuid(luid);
    }

    internal static void EnsureResultIsNull(NativeMethods.ERROR result)
    {
        if (result != NativeMethods.ERROR.ERROR_SUCCESS)
        {
            throw new InvalidOperationException(
                $"Native method returns error: {result:G}",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }
    }
}
