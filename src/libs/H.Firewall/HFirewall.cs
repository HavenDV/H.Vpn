using System.Net;
using System.Net.Sockets;
using System.Reflection;
using H.IpHlpApi;
using H.Wfp;
using H.Wfp.Interop;

namespace H.Firewall;

public class HFirewall : IDisposable
{
    #region Properties

    public IntPtrWrapper WfpSession { get; private set; } = new IntPtrWrapper();
    public Settings Settings { get; private set; } = new Settings();
    public string VpnIp { get; private set; } = string.Empty;
    public bool IsEnabled => !WfpSession.IsEmpty;

    #endregion

    #region Events

    public event EventHandler<string>? LogReceived;

    private void OnLogReceived(string value)
    {
        LogReceived?.Invoke(this, value);
    }

    #endregion

    #region Methods

    public void ChangeSettings(Settings settings, string vpnIp)
    {
        if (!string.IsNullOrWhiteSpace(VpnIp))
        {
            RemoveSplitTunnelRoutes(VpnIp);
        }

        if (IsEnabled)
        {
            if (Settings.Equals(settings) &&
                VpnIp == vpnIp)
            {
                return;
            }

            Dispose();
        }

        if (!settings.EnableKillSwitch &&
            settings.SplitTunnelingMode == SplitTunnelingMode.Off)
        {
            return;
        }

        if (settings.SplitTunnelingMode != SplitTunnelingMode.Off)
        {
            try
            {
                //StartServiceIfNotRunning("STDriver");
            }
            catch (Exception)
            {
                settings.SplitTunnelingMode = SplitTunnelingMode.Off;
            }
        }

        StartSession(settings, vpnIp);

        if (!string.IsNullOrWhiteSpace(VpnIp) &&
            VpnIp != vpnIp)
        {
            RemoveSplitTunnelRoutes(VpnIp);
        }

        if (!string.IsNullOrWhiteSpace(vpnIp))
        {
            AddSplitTunnelRoutes(vpnIp);
        }

        Settings = settings;
        VpnIp = vpnIp;
    }

    public void AddSplitTunnelRoutes(string vpnIp)
    {
        try
        {
            var (index, metric) = NetworkMethods.FindInterfaceIndexAndMetricByIp(IPAddress.Parse(vpnIp));
            if (index == 0)
            {
                throw new ArgumentException($"Failed to find interface index and metric for {vpnIp}");
            }

            try
            {
                NetworkMethods.AddRoute(IPNetwork.Parse("0.0.0.0/128.0.0.0"), index, metric);
            }
            catch (Exception exception)
            {
                OnLogReceived(exception.Message);
            }

            try
            {
                NetworkMethods.AddRoute(IPNetwork.Parse("128.0.0.0/128.0.0.0"), index, metric);
            }
            catch (Exception exception)
            {
                OnLogReceived(exception.Message);
            }
        }
        catch (Exception exception)
        {
            OnLogReceived($"{exception}");
        }
    }

    public void RemoveSplitTunnelRoutes(string vpnIp)
    {
        try
        {
            var (index, _) = NetworkMethods.FindInterfaceIndexAndMetricByIp(IPAddress.Parse(vpnIp));
            if (index == 0)
            {
                throw new ArgumentException($"Failed to find interface index and metric for {vpnIp}");
            }

            try
            {
                NetworkMethods.DeleteRoute(IPNetwork.Parse("128.0.0.0/128.0.0.0"), index);
            }
            catch (Exception exception)
            {
                OnLogReceived(exception.Message);
            }

            try
            {
                NetworkMethods.DeleteRoute(IPNetwork.Parse("0.0.0.0/128.0.0.0"), index);
            }
            catch (Exception exception)
            {
                OnLogReceived(exception.Message);
            }
        }
        catch (Exception exception)
        {
            OnLogReceived($"{exception}");
        }
    }

    public void StartSession(Settings settings, string vpnIp)
    {
        Start();

        RunTransaction(ptr =>
        {
            var keys = RegisterKeys();
            if (settings.EnableKillSwitch)
            {
                // H.Wfp-Service.exe
                PermitAppId(keys, GetServiceProcessPath(), 15);
                // OpenVPN.exe
                PermitAppId(keys, GetOpenVpnPath(), 14);

                // H.Wfp.exe
#if DEBUG
                PermitAppId(keys, @"C:\Program Files\H.Wfp\H.Wfp.exe", 13);
#else
                PermitAppId(keys, GetGuiProcessPath(), 13);
#endif

                // LAN
                if (settings.AllowLan)
                {
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("192.168.0.0/16"));
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("172.16.0.0/12"));
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("10.0.0.0/8"));
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("224.0.0.0/4"));
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("169.254.0.0/16"));
                    PermitRemoteSubNetworkV4(keys, 12, IPNetwork.Parse("255.255.255.255/32"));
                }

                // DNS
                var dnsServers = new List<IPAddress>();
                if (!string.IsNullOrWhiteSpace(settings.PrimaryDns))
                {
                    dnsServers.Add(IPAddress.Parse(settings.PrimaryDns));
                }
                if (!string.IsNullOrWhiteSpace(settings.SecondaryDns))
                {
                    dnsServers.Add(IPAddress.Parse(settings.SecondaryDns));
                }
                if (!dnsServers.Any())
                {
                    dnsServers.Add(IPAddress.Parse("10.255.0.1"));
                }
                PermitDns(keys, 11, 10, dnsServers);

                // IKEv2
                PermitLocalSubNetworkV4(keys, 9, IPNetwork.Parse("10.0.0.0/8"));
                PermitProtocolV4(keys, 9, WtIPProto.cIPPROTO_IPinIP);

                // TAP adapter
                PermitNetworkInterface(keys, 2, NetworkMethods.FindTapAdapterLuid());

                // Localhost
                PermitLoopback(keys, 1);

                // Block everything not allowed explicitly
                BlockAll(keys, 0);
            }

            switch (settings.SplitTunnelingMode)
            {
                case SplitTunnelingMode.AllowSelectedApps:
                    {
                        RegisterCallout(keys);

                        var localProviderContextKey = RegisterProviderContext(keys, IPAddress.Parse(settings.LocalIp));
                        AllowSplitApps(
                            keys,
                            settings.SplitTunnelingApps,
                            8,
                            localProviderContextKey,
                            true);

                        var vpnProviderContextKey = RegisterProviderContext(keys, IPAddress.Parse(vpnIp));
                        AllowSplitApps(
                            keys,
                            settings.SplitTunnelingApps,
                            8,
                            vpnProviderContextKey,
                            false);
                        break;
                    }

                case SplitTunnelingMode.DisallowSelectedApps:
                    {
                        RegisterCallout(keys);

                        var localProviderContextKey = RegisterProviderContext(keys, IPAddress.Parse(settings.LocalIp));
                        AllowSplitApps(
                            keys,
                            settings.SplitTunnelingApps,
                            8,
                            localProviderContextKey,
                            false);

                        var vpnProviderContextKey = RegisterProviderContext(keys, IPAddress.Parse(vpnIp));
                        AllowSplitApps(
                            keys,
                            settings.SplitTunnelingApps,
                            8,
                            vpnProviderContextKey,
                            true);
                        break;
                    }
            }
        });
    }

    public void RunTransaction(Action<IntPtr> action)
    {
        var ptr = (IntPtr)WfpSession;

        WfpMethods.BeginTransaction(ptr);

        try
        {
            action.Invoke(ptr);
        }
        catch
        {
            WfpMethods.AbortTransaction(ptr);
            throw;
        }

        WfpMethods.CommitTransaction(ptr);
    }

    public void Disable()
    {
        Dispose();
        Settings.EnableKillSwitch = false;
        Settings.AllowLan = false;
    }

    public void Start()
    {
        WfpSession = new IntPtrWrapper(
            WfpMethods.CreateWfpSession("H.Wfp", "H.Wfp dynamic session"),
            WfpMethods.CloseWfpSession);
    }

    public Tuple<Guid, Guid> RegisterKeys()
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

        return new Tuple<Guid, Guid>(providerGuid, subLayerGuid);
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
    private static Guid cHVPN_WFP_CALLOUT_V4 { get; } = new Guid(
        0x2da40468, 0xb926, 0x4402,
        0xb3, 0xf8, 0xcb, 0x4e, 0x91, 0x27, 0x01, 0x59);

    public void RegisterCallout(Tuple<Guid, Guid> wfpKeys)
    {
        WfpMethods.AddCallout(
            WfpSession,
            cHVPN_WFP_CALLOUT_V4,
            wfpKeys.Item1,
            NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
            "H.Wfp",
            "Split tunneling callout (IPv4)");
    }

    public Guid RegisterProviderContext(Tuple<Guid, Guid> wfpKeys, IPAddress ipAddress)
    {
        return WfpMethods.AddProviderContext(
            WfpSession,
            wfpKeys.Item1,
            "H.Wfp",
            "Register provider context for split tunneling callout driver",
            ipAddress);
    }

    public void EnableSplitApp(
        Tuple<Guid, Guid> wfpKeys,
        string appPath,
        byte weight,
        Guid providerContextKey)
    {
        AllowSplitApps(wfpKeys, new[] { appPath }, weight, providerContextKey, false);
    }

    public void AllowSplitApps(
        Tuple<Guid, Guid> wfpKeys,
        ICollection<string> paths,
        byte weight,
        Guid providerContextKey,
        bool reversed)
    {
        var appIds = paths
            .Select(GetAppId)
            .ToArray();

        try
        {
            foreach (var appId in appIds)
            {
                PermitAppId(wfpKeys, appId, weight);
            }

            AllowSplitAppIds(wfpKeys, appIds, weight, providerContextKey, reversed);
        }
        finally
        {
            foreach (var appId in appIds)
            {
                appId.Dispose();
            }
        }
    }

    public void AllowSplitAppIds(
        Tuple<Guid, Guid> wfpKeys,
        IntPtrWrapper[] appIds,
        byte weight,
        Guid providerContextKey,
        bool reversed)
    {
        WfpMethods.AllowSplitAppIds(
            WfpSession,
            wfpKeys.Item1,
            NativeConstants.cFWPM_SUBLAYER_UNIVERSAL,
            NativeConstants.cFWPM_LAYER_ALE_BIND_REDIRECT_V4,
            appIds,
            weight,
            providerContextKey,
            cHVPN_WFP_CALLOUT_V4,
            reversed,
            "H.Wfp",
            "Enable split tunneling using callout (IPv4)");
    }

    public void EnableSplitAppId(
        Tuple<Guid, Guid> wfpKeys,
        IntPtrWrapper appId,
        byte weight,
        Guid providerContextKey)
    {
        AllowSplitAppIds(wfpKeys, new[] { appId }, weight, providerContextKey, false);
    }

    public void PermitAppId(Tuple<Guid, Guid> wfpKeys, IntPtrWrapper appId, byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitAppId(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                appId,
                weight,
                "H.Wfp",
                $"Permit unrestricted traffic ({pair.Key})");
        }
    }

    public void PermitAppId(Tuple<Guid, Guid> wfpKeys, string path, byte weight)
    {
        try
        {
            using (var id = GetAppId(path))
            {
                PermitAppId(wfpKeys, id, weight);
            }
        }
        catch (Exception exception)
        {
            throw new InvalidOperationException($"PermitAppId failed for path: {path}", exception);
        }
    }

    public void PermitLoopback(Tuple<Guid, Guid> wfpKeys, byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitLoopback(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weight,
                "H.Wfp",
                $"Permit on loopback ({pair.Key})");
        }
    }

    public void BlockAll(Tuple<Guid, Guid> wfpKeys, byte weight)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.BlockAll(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weight,
                "H.Wfp",
                $"Block all ({pair.Key})");
        }
    }

    public void PermitDns(Tuple<Guid, Guid> wfpKeys, byte weightAllow, byte weightDeny, ICollection<IPAddress> addresses)
    {
        if (weightDeny >= weightAllow)
        {
            throw new ArgumentException("The allow weight must be greater than the deny weight");
        }

        foreach (var pair in Layers)
        {
            WfpMethods.BlockDns(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weightDeny,
                "H.Wfp",
                $"Block DNS ({pair.Key})");
        }

        foreach (var pair in V4Layers)
        {
            WfpMethods.AllowDnsV4(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weightDeny,
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork),
                "H.Wfp",
                $"Allow DNS ({pair.Key})");
        }

        foreach (var pair in V6Layers)
        {
            WfpMethods.AllowDnsV6(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weightDeny,
                addresses.Where(address => address.AddressFamily == AddressFamily.InterNetworkV6),
                "H.Wfp",
                $"Allow DNS ({pair.Key})");
        }
    }

    public void PermitNetworkInterface(Tuple<Guid, Guid> wfpKeys, byte weight, ulong ifLuid)
    {
        foreach (var pair in Layers)
        {
            WfpMethods.PermitNetworkInterface(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weight,
                ifLuid,
                "H.Wfp",
                $"Permit traffic on TAP adapter ({pair.Key})");
        }
    }

    public void PermitSubNetworkV4(
        Tuple<Guid, Guid> wfpKeys,
        byte weight,
        IPAddress address,
        IPAddress mask,
        bool isLocalAddress)
    {
        foreach (var pair in V4Layers)
        {
            WfpMethods.PermitSubNetworkV4(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
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
        Tuple<Guid, Guid> wfpKeys,
        byte weight,
        IPNetwork network)
    {
        PermitSubNetworkV4(wfpKeys, weight, network.Network, network.Netmask, true);
    }

    public void PermitRemoteSubNetworkV4(
        Tuple<Guid, Guid> wfpKeys,
        byte weight,
        IPNetwork network)
    {
        PermitSubNetworkV4(wfpKeys, weight, network.Network, network.Netmask, false);
    }

    public void PermitUdpPortV4(Tuple<Guid, Guid> wfpKeys, byte weight, ushort port)
    {
        foreach (var pair in new Dictionary<string, Guid>
        {
            { "IPv4 inbound", NativeConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
            { "IPv4 established", NativeConstants.FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 },
        })
        {
            WfpMethods.PermitUdpPortV4(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weight,
                port,
                "H.Wfp",
                $"Permit traffic on UDP port ({pair.Key})");
        }
    }

    public void PermitProtocolV4(Tuple<Guid, Guid> wfpKeys, byte weight, WtIPProto proto)
    {
        foreach (var pair in V4Layers)
        {
            WfpMethods.PermitProtocolV4(
                WfpSession,
                wfpKeys.Item1,
                wfpKeys.Item2,
                pair.Value,
                weight,
                (byte)proto,
                "H.Wfp",
                $"Permit traffic for protocol ({pair.Key})");
        }
    }

    public static IntPtrWrapper GetAppId(string fileName)
    {
        fileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
        if (!File.Exists(fileName))
        {
            throw new ArgumentException($"File is not exists: {fileName}");
        }

        return WfpMethods.GetAppIdFromFileName(fileName);
    }

    public static string GetServiceProcessPath()
    {
        var path = Assembly.GetEntryAssembly()?.Location ?? string.Empty;
        if (path == null || string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException("This method only works when running exe files.");
        }

        return path;
    }

    public static string GetServiceProcessDirectory()
    {
        return Path.GetDirectoryName(GetServiceProcessPath()) ?? string.Empty;
    }

    public static string GetOpenVpnPath()
    {
        return Path.Combine(GetServiceProcessDirectory(), "OpenVPN", "openvpn.exe");
    }

    public static string GetGuiProcessPath()
    {
        return Path.Combine(Path.GetDirectoryName(GetServiceProcessDirectory()) ?? string.Empty, "H.Wfp.exe");
    }

    public void Dispose()
    {
        WfpSession.Dispose();
    }

    #endregion
}
