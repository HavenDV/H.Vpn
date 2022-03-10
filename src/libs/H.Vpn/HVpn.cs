using H.Firewall;
using H.IpHlpApi;
using H.OpenVpn;
using System.Net;
using System.Reflection;

namespace H.Vpn;

public class HVpn : IDisposable
{
    #region Properties

    public HFirewall Firewall { get; } = new HFirewall();
    public HOpenVpn OpenVpn { get; set; } = new HOpenVpn();
    public ServiceStatus Status { get; } = new ServiceStatus
    {
        Status = "disconnected",
    };
    public FirewallSettings FirewallSettings { get; private set; } = new();
    public string VpnIp { get; private set; } = string.Empty;

    #endregion

    #region Events

    public event EventHandler<Exception>? ExceptionOccurred;
    public event EventHandler<string>? LogReceived;

    public event EventHandler<ServiceStatus>? StatusChanged;
    public event EventHandler<(long bytesIn, long bytesOut)>? TrafficStatsChanged;

    private void OnExceptionOccurred(Exception value)
    {
        OnLogReceived($"Exception: {value}");

        ExceptionOccurred?.Invoke(this, value);
    }

    private void OnLogReceived(string value)
    {
        LogReceived?.Invoke(this, value);
    }

    private void OnStatusChanged()
    {
        StatusChanged?.Invoke(this, Status);
    }

    private void OnTrafficStatsChanged((long bytesIn, long bytesOut) value)
    {
        TrafficStatsChanged?.Invoke(this, value);
    }

    #endregion

    #region Methods

    public void ChangeFirewallSettings(FirewallSettings settings, string vpnIp)
    {
        settings = settings ?? throw new ArgumentNullException(nameof(settings));

        if (!string.IsNullOrWhiteSpace(VpnIp))
        {
            try
            {
                NetworkMethods.RemoveSplitTunnelRoutes(IPAddress.Parse(VpnIp));
            }
            catch (Exception exception)
            {
                OnLogReceived($"{exception}");
            }
        }

        if (Firewall.IsEnabled)
        {
            if (FirewallSettings.Equals(settings) &&
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

        StartFirewall(settings, vpnIp);

        if (!string.IsNullOrWhiteSpace(VpnIp) &&
            VpnIp != vpnIp)
        {
            try
            {
                NetworkMethods.RemoveSplitTunnelRoutes(IPAddress.Parse(VpnIp));
            }
            catch (Exception exception)
            {
                OnLogReceived($"{exception}");
            }
        }

        if (!string.IsNullOrWhiteSpace(vpnIp))
        {
            try
            {
                NetworkMethods.AddSplitTunnelRoutes(IPAddress.Parse(vpnIp));
            }
            catch (Exception exception)
            {
                OnLogReceived($"{exception}");
            }
        }

        FirewallSettings = settings;
        VpnIp = vpnIp;
    }

    public static string GetServiceProcessPath()
    {
        var path = Assembly.GetEntryAssembly()?.Location ?? string.Empty;
        if (string.IsNullOrWhiteSpace(path))
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

    public void StartFirewall(FirewallSettings settings, string vpnIp)
    {
        Firewall.Start();
        Firewall.RunTransaction(ptr =>
        {
            var (providerKey, subLayerKey) = Firewall.RegisterKeys();
            if (settings.EnableKillSwitch)
            {
                // H.Wfp-Service.exe
                Firewall.PermitAppId(providerKey, subLayerKey, GetServiceProcessPath(), 15);
                // OpenVPN.exe
                Firewall.PermitAppId(providerKey, subLayerKey, GetOpenVpnPath(), 14);

                // H.Wfp.exe
#if DEBUG
                Firewall.PermitAppId(providerKey, subLayerKey, @"C:\Program Files\H.Wfp\H.Wfp.exe", 13);
#else
                Firewall.PermitAppId(providerKey, subLayerKey, GetGuiProcessPath(), 13);
#endif

                if (settings.AllowLan)
                {
                    Firewall.PermitLan(providerKey, subLayerKey, 12);
                }

                Firewall.PermitDns(providerKey, subLayerKey, 11, 10, settings.PrimaryDns, settings.SecondaryDns);
                Firewall.PermitIKEv2(providerKey, subLayerKey, 9);
                // Permit Tap Adapter
                Firewall.PermitNetworkInterface(providerKey, subLayerKey, 2, NetworkMethods.FindTapAdapterLuid());
                Firewall.PermitLocalhost(providerKey, subLayerKey, 1);

                // Block everything not allowed explicitly
                Firewall.BlockAll(providerKey, subLayerKey, 0);
            }

            switch (settings.SplitTunnelingMode)
            {
                case SplitTunnelingMode.AllowSelectedApps:
                    {
                        Firewall.EnableSplitTunnelingOnlyForSelectedApps(
                            providerKey,
                            subLayerKey,
                            8,
                            IPAddress.Parse(settings.LocalIp),
                            IPAddress.Parse(vpnIp),
                            settings.SplitTunnelingApps.ToArray());
                        break;
                    }

                case SplitTunnelingMode.DisallowSelectedApps:
                    {
                        Firewall.EnableSplitTunnelingExcludeSelectedApps(
                            providerKey,
                            subLayerKey,
                            8,
                            IPAddress.Parse(settings.LocalIp),
                            IPAddress.Parse(vpnIp),
                            settings.SplitTunnelingApps.ToArray());
                        break;
                    }
            }
        });
    }

    public void StopFirewall()
    {
        Firewall.Stop();
        FirewallSettings.EnableKillSwitch = false;
        FirewallSettings.AllowLan = false;
    }

    public async Task StartVpnAsync(
        string? config, 
        string? username,
        string? password, 
        CancellationToken cancellationToken = default)
    {
        OpenVpn.Dispose();
        OpenVpn = new HOpenVpn();
        OpenVpn.ExceptionOccurred += (_, exception) => OnExceptionOccurred(exception);
        OpenVpn.StateChanged += async (_, state) =>
        {
            try
            {
                switch (state)
                {
                    case VpnState.Restarting:
                    case VpnState.DisconnectingToReconnect:
                        Status.IsReconnecting = true;
                        break;

                    case VpnState.Connected:
                    case VpnState.Disconnecting:
                        Status.IsReconnecting = false;
                        break;
                }

                var subStatus = $"{state:G}".ToLowerInvariant();
                switch (state)
                {
                    case VpnState.Preparing:
                    case VpnState.Started:
                    case VpnState.Initialized:
                    case VpnState.Restarting:
                    case VpnState.Connecting:
                        Status.Status = "connecting";
                        Status.SubStatus = subStatus;

                        OnStatusChanged();
                        break;

                    case VpnState.Connected:
                        await OpenVpn.SubscribeByteCountAsync().ConfigureAwait(false);

                        Status.Status = "connected";
                        Status.ConnectionStartDate = DateTime.UtcNow;
                        Status.LocalInterfaceAddress = OpenVpn.LocalInterfaceAddress;
                        Status.RemoteIpdAddress = OpenVpn.RemoteIpAddress;
                        Status.RemoteIpPort = OpenVpn.RemoteIpPort;

                        OnStatusChanged();
                        break;

                    case VpnState.Disconnecting:
                    case VpnState.DisconnectingToReconnect:
                    case VpnState.Exiting:
                        Status.Status = "disconnecting";
                        Status.SubStatus = subStatus;

                        OnStatusChanged();
                        break;

                    case VpnState.Inactive:
                        Status.Status = "disconnected";

                        OnStatusChanged();
                        break;

                    case VpnState.Failed:
                        Status.Status = "failed";
                        //Status.LastErrorCode = code;
                        //Status.LastErrorMessage = message ?? "Unexpected error";

                        OnStatusChanged();

                        Status.Status = "disconnected";

                        OnStatusChanged();
                        break;
                }
            }
            catch (Exception exception)
            {
                OnExceptionOccurred(exception);
            }
        };
        OpenVpn.InternalStateObtained += (_, state) =>
        {
            OnLogReceived($@"OpenVPN internal state obtained: 
Name: {state.Name},
Description: {state.Description},
LocalIp: {state.LocalIp},
RemoteIp: {state.RemoteIp},
Time: {state.Time:T}");
        };
        OpenVpn.BytesInCountChanged += (_, count) =>
        {
            OnLogReceived($"OpenVPN BytesInCount: {count}");
            OnTrafficStatsChanged((count, OpenVpn.BytesOutCount));
        };
        OpenVpn.BytesOutCountChanged += (_, count) =>
        {
            OnLogReceived($"OpenVPN BytesOutCount: {count}");
            OnTrafficStatsChanged((OpenVpn.BytesInCount, count));
        };
        OpenVpn.LogObtained += (_, message) =>
        {
            OnLogReceived($"OpenVPN Log: {message}");
        };
        OpenVpn.ConsoleLineReceived += (_, message) =>
        {
            OnLogReceived($"OpenVPN Console Received: {message}");
        };
        OpenVpn.ManagementLineReceived += (_, message) =>
        {
            OnLogReceived($"OpenVPN Management Received: {message}");
        };
        OpenVpn.ConsoleLineSent += (_, message) =>
        {
            OnLogReceived($"OpenVPN Console Sent: {message}");
        };
        OpenVpn.ManagementLineSent += (_, message) =>
        {
            OnLogReceived($"OpenVPN Management Sent: {message}");
        };
        OpenVpn.Start(config,  username,  password);

        await OpenVpn.WaitAuthenticationAsync(cancellationToken).ConfigureAwait(false);

        await OpenVpn.SubscribeStateAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task StopVpnAsync(CancellationToken cancellationToken = default)
    {
        //isReconnecting = false
        switch (OpenVpn.VpnState)
        {
            case VpnState.Preparing:
            case VpnState.Started:
            case VpnState.Initialized:
                OpenVpn.VpnState = VpnState.Exiting;
                break;

            case VpnState.Connecting:
            case VpnState.Restarting:
            case VpnState.Connected:
                OpenVpn.VpnState = VpnState.Disconnecting;

                await OpenVpn.SendSignalAsync(Signal.SIGTERM, cancellationToken).ConfigureAwait(false);

                OpenVpn.WaitForExit(TimeSpan.FromSeconds(5));
                OpenVpn.VpnState = VpnState.Inactive;
                break;

            // Force change event.
            case VpnState.DisconnectingToReconnect:
            case VpnState.Exiting:
            case VpnState.Inactive:
            case VpnState.Failed:
                OpenVpn.VpnState = OpenVpn.VpnState;
                break;
        }

        OpenVpn.Dispose();
    }

    public static Version GetVersion()
    {
        return Assembly.GetExecutingAssembly().GetName().Version;
    }

    public void Stop()
    {
        Dispose();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            OpenVpn.Dispose();
            Firewall.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #endregion
}
