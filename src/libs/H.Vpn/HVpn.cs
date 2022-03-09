using H.Firewall;
using H.OpenVpn;
using System.Reflection;

namespace H.Vpn
{
    public class HVpn : IDisposable
    {
        #region Properties

        public HFirewall Firewall { get; } = new HFirewall();
        public HOpenVpn OpenVpn { get; set; } = new HOpenVpn();
        public ServiceStatus Status { get; } = new ServiceStatus
        {
            Status = "disconnected",
        };

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

        #region Constructors

        public HVpn()
        {
            Firewall.LogReceived += (_, message) => OnLogReceived($"Firewall LogReceived: {message}");
        }

        #endregion

        #region Methods

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
                            await OpenVpn.SubscribeByteCountAsync();

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

            await OpenVpn.WaitAuthenticationAsync(cancellationToken);

            await OpenVpn.SubscribeStateAsync(cancellationToken);
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

                    await OpenVpn.SendSignalAsync(Signal.SIGTERM);

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

        public Version GetVersion()
        {
            return Assembly.GetExecutingAssembly().GetName().Version;
        }

        public void Stop()
        {
            Dispose();
        }

        public void Dispose()
        {
            OpenVpn.Dispose();
            Firewall.Dispose();
        }

        #endregion
    }
}
