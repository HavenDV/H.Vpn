using H.Wfp;
using H.Wfp.Interop;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace H.Firewall;

public class HFirewall : IDisposable
{
    #region Properties

    public SafeHandle WfpSession { get; private set; } = new SafeWfpSessionHandle();
    public bool IsEnabled => !WfpSession.IsInvalid;

    #endregion

    #region Methods

    public void PermitLan(
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("192.168.0.0/16"));
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("172.16.0.0/12"));
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("10.0.0.0/8"));
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("224.0.0.0/4"));
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("169.254.0.0/16"));
        PermitRemoteSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("255.255.255.255/32"));
    }

    public void PermitDns(
        Guid providerKey,
        Guid subLayerKey,
        byte weightAllow,
        byte weightDeny,
        params string[] servers)
    {
        var dnsServers = new List<IPAddress>();
        foreach (var server in servers
            .Where(static server => !string.IsNullOrWhiteSpace(server)))
        {
            dnsServers.Add(IPAddress.Parse(server));
        }
        if (!dnsServers.Any())
        {
            dnsServers.Add(IPAddress.Parse("10.255.0.1"));
        }
        PermitDns(providerKey, subLayerKey, weightAllow, weightDeny, dnsServers);
    }

    public void PermitIKEv2(
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        PermitLocalSubNetworkV4(providerKey, subLayerKey, weight, IPNetwork.Parse("10.0.0.0/8"));
        PermitProtocolV4(providerKey, subLayerKey, weight, WtIPProto.cIPPROTO_IPinIP);
    }

    public void PermitLocalhost(
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        PermitLoopback(providerKey, subLayerKey, weight);
    }

    //public void EnableSplitTunnelingForSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    bool reversed,
    //    params string[] applications)
    //{
    //    RegisterCallout(providerKey);

    //    var localProviderContextKey = RegisterProviderContext(
    //        providerKey,
    //        localIp);
    //    AllowSplitApps(
    //        providerKey,
    //        subLayerKey,
    //        applications,
    //        weight,
    //        localProviderContextKey,
    //        !reversed);

    //    var vpnProviderContextKey = RegisterProviderContext(
    //        providerKey,
    //        vpnIp);
    //    AllowSplitApps(
    //        providerKey,
    //        subLayerKey,
    //        applications,
    //        weight,
    //        vpnProviderContextKey,
    //        reversed);
    //}

    //public void EnableSplitTunnelingOnlyForSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    params string[] applications)
    //{
    //    EnableSplitTunnelingForSelectedApps(
    //        providerKey,
    //        subLayerKey,
    //        weight,
    //        localIp,
    //        vpnIp,
    //        false,
    //        applications);
    //}

    //public void EnableSplitTunnelingExcludeSelectedApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    byte weight,
    //    IPAddress localIp,
    //    IPAddress vpnIp,
    //    params string[] applications)
    //{
    //    EnableSplitTunnelingForSelectedApps(
    //        providerKey,
    //        subLayerKey,
    //        weight,
    //        localIp,
    //        vpnIp,
    //        true,
    //        applications);
    //}

    public void RunTransaction(Action<SafeHandle> action)
    {
        action = action ?? throw new ArgumentNullException(nameof(action));

        WfpMethods.BeginTransaction(WfpSession);

        try
        {
            action.Invoke(WfpSession);
        }
        catch
        {
            WfpMethods.AbortTransaction(WfpSession);
            throw;
        }

        WfpMethods.CommitTransaction(WfpSession);
    }

    public void Start()
    {
        WfpSession = WfpMethods.CreateWfpSession("H.Wfp", "H.Wfp dynamic session");
    }

    public void Stop()
    {
        Dispose();
    }

    public (Guid providerGuid, Guid subLayerGuid) RegisterKeys()
    {
        var providerGuid = WfpMethods.AddProvider(
            WfpSession,
            "H.Wfp",
            "H.Wfp provider");
        var subLayerGuid = WfpMethods.AddSubLayer(
            WfpSession,
            providerGuid,
            "H.Wfp filters",
            "Permissive and blocking filters");

        return (providerGuid, subLayerGuid);
    }

    private static IReadOnlyDictionary<string, Guid> V4Layers { get; } = new Dictionary<string, Guid>
    {
        { "IPv4 outbound", NativeConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4 },
        { "IPv4 inbound", NativeConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
    };

    private static IReadOnlyDictionary<string, Guid> V6Layers { get; } = new Dictionary<string, Guid>
    {
        { "IPv6 outbound", NativeConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6 },
        { "IPv6 inbound", NativeConstants.cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 },
    };

    private static IReadOnlyDictionary<string, Guid> Layers => V4Layers
        .Concat(V6Layers)
        .ToDictionary(pair => pair.Key, pair => pair.Value);

    // ReSharper disable once InconsistentNaming
    // ReSharper disable once UnusedMember.Local
    //private static Guid cHVPN_WFP_CALLOUT_V4 { get; } = new Guid(
    //    0x2da40468, 0xb926, 0x4402,
    //    0xb3, 0xf8, 0xcb, 0x4e, 0x91, 0x27, 0x01, 0x59);

    //public void RegisterCallout(
    //    Guid providerKey)
    //{
    //    WfpMethods.AddCallout(
    //        WfpSession,
    //        cHVPN_WFP_CALLOUT_V4,
    //        providerKey,
    //        NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
    //        "H.Wfp",
    //        "Split tunneling callout (IPv4)");
    //}

    //public Guid RegisterProviderContext(
    //    Guid providerKey,
    //    IPAddress ipAddress)
    //{
    //    return WfpMethods.AddProviderContext(
    //        WfpSession,
    //        providerKey,
    //        "H.Wfp",
    //        "Register provider context for split tunneling callout driver",
    //        ipAddress);
    //}

    //public void EnableSplitApp(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    string appPath,
    //    byte weight,
    //    Guid providerContextKey)
    //{
    //    AllowSplitApps(providerKey, subLayerKey, new[] { appPath }, weight, providerContextKey, false);
    //}

    //public void AllowSplitApps(
    //    Guid providerKey,
    //    Guid subLayerKey,
    //    ICollection<string> paths,
    //    byte weight,
    //    Guid providerContextKey,
    //    bool reversed)
    //{
    //    var appIds = paths
    //        .Select(GetAppId)
    //        .ToArray();

    //    try
    //    {
    //        foreach (var appId in appIds)
    //        {
    //            PermitAppId(providerKey, subLayerKey, appId, weight);
    //        }

    //        AllowSplitAppIds(providerKey, appIds, weight, providerContextKey, reversed);
    //    }
    //    finally
    //    {
    //        foreach (var appId in appIds)
    //        {
    //            appId.Dispose();
    //        }
    //    }
    //}

    //public void AllowSplitAppIds(
    //    Guid providerKey,
    //    SafeFwpmHandle[] appIds,
    //    byte weight,
    //    Guid providerContextKey,
    //    bool reversed)
    //{
    //    WfpMethods.AllowSplitAppIds(
    //        WfpSession,
    //        providerKey,
    //        NativeConstants.cFWPM_SUBLAYER_UNIVERSAL,
    //        NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
    //        appIds,
    //        weight,
    //        providerContextKey,
    //        cHVPN_WFP_CALLOUT_V4,
    //        reversed,
    //        "H.Wfp",
    //        "Enable split tunneling using callout (IPv4)");
    //}

    //public void EnableSplitAppId(
    //    Guid providerKey,
    //    SafeFwpmHandle appId,
    //    byte weight,
    //    Guid providerContextKey)
    //{
    //    AllowSplitAppIds(providerKey, new[] { appId }, weight, providerContextKey, false);
    //}

    public void PermitAppId(
        Guid providerKey,
        Guid subLayerKey,
        SafeFwpmHandle appId,
        byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitAppId(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                appId,
                weight,
                "H.Wfp",
                $"Permit unrestricted traffic ({pair.Key})");
        }
    }

    public void PermitAppId(
        Guid providerKey,
        Guid subLayerKey,
        string path,
        byte weight)
    {
        try
        {
            using var id = GetAppId(path);

            PermitAppId(providerKey, subLayerKey, id, weight);
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException($"PermitAppId failed for path: {path}", exception);
        }
    }

    public void PermitLoopback(
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitLoopback(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                "H.Wfp",
                $"Permit on loopback ({pair.Key})");
        }
    }

    public void BlockAll(
        Guid providerKey,
        Guid subLayerKey,
        byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.BlockAll(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                "H.Wfp",
                $"Block all ({pair.Key})");
        }
    }

    public void PermitDns(
        Guid providerKey,
        Guid subLayerKey,
        byte weightAllow,
        byte weightDeny,
        ICollection<IPAddress> addresses)
    {
        if (weightDeny >= weightAllow)
        {
            throw new ArgumentException("The allow weight must be greater than the deny weight");
        }

        foreach (var pair in Layers)
        {
            WfpMethods.BlockDns(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weightDeny,
                "H.Wfp",
                $"Block DNS ({pair.Key})");
        }

        foreach (var pair in V4Layers)
        {
            WfpMethods.AllowDnsV4(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weightDeny,
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork),
                "H.Wfp",
                $"Allow DNS ({pair.Key})");
        }

        // foreach (var pair in V6Layers)
        // {
        //     WfpMethods.AllowDnsV6(
        //         WfpSession,
        //         providerKey,
        //         subLayerKey,
        //         pair.Value,
        //         weightDeny,
        //         addresses.Where(address => address.AddressFamily == AddressFamily.InterNetworkV6),
        //         "H.Wfp",
        //         $"Allow DNS ({pair.Key})");
        // }
    }

    public void PermitNetworkInterface(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ulong ifLuid)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitNetworkInterface(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                ifLuid,
                "H.Wfp",
                $"Permit traffic on TAP adapter ({pair.Key})");
        }
    }

    public void PermitSubNetworkV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPAddress address,
        IPAddress mask,
        bool isLocalAddress)
    {
        foreach (var pair in V4Layers)
        {
            WfpMethods.PermitSubNetworkV4(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                address,
                mask,
                isLocalAddress,
                "H.Wfp",
                $"Permit traffic on LAN network ({pair.Key})");
        }
    }

    public void PermitLocalSubNetworkV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPNetwork network)
    {
        network = network ?? throw new ArgumentNullException(nameof(network));

        PermitSubNetworkV4(providerKey, subLayerKey, weight, network.Network, network.Netmask, true);
    }

    public void PermitRemoteSubNetworkV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        IPNetwork network)
    {
        network = network ?? throw new ArgumentNullException(nameof(network));

        PermitSubNetworkV4(providerKey, subLayerKey, weight, network.Network, network.Netmask, false);
    }

    public void PermitTcpPortV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ushort port)
    {
        foreach (var pair in new Dictionary<string, Guid>
        {
            { "IPv4 inbound", NativeConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
            { "IPv4 established", NativeConstants.FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 },
        })
        {
            WfpMethods.PermitTcpPortV4(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                port,
                "H.Wfp",
                $"Permit traffic on TCP port ({pair.Key})");
        }
    }

    public void PermitUdpPortV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        ushort port)
    {
        foreach (var pair in new Dictionary<string, Guid>
        {
            { "IPv4 inbound", NativeConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
            { "IPv4 established", NativeConstants.FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 },
        })
        {
            WfpMethods.PermitUdpPortV4(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                port,
                "H.Wfp",
                $"Permit traffic on UDP port ({pair.Key})");
        }
    }

    public void PermitProtocolV4(
        Guid providerKey,
        Guid subLayerKey,
        byte weight,
        WtIPProto proto)
    {
        foreach (var pair in V4Layers)
        {
            WfpMethods.PermitProtocolV4(
                WfpSession,
                providerKey,
                subLayerKey,
                pair.Value,
                weight,
                (byte)proto,
                "H.Wfp",
                $"Permit traffic for protocol ({pair.Key})");
        }
    }

    public static SafeFwpmHandle GetAppId(string fileName)
    {
        fileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
        if (!File.Exists(fileName))
        {
            throw new ArgumentException($"File is not exists: {fileName}");
        }

        return WfpMethods.GetAppIdFromFileName(fileName);
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
