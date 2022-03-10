using H.Firewall;
using H.Vpn;
using H.VpnService.Models;

namespace H.VpnService
{
    public class HVpnService : IDisposable
    {
        #region Properties

        private IpcServer IpcServer { get; } = new IpcServer();
        private HVpn Vpn { get; } = new HVpn();

        #endregion

        #region Events

        public event EventHandler<Exception>? ExceptionOccurred;
        public event EventHandler<string>? LogReceived;

        private void OnExceptionOccurred(Exception value)
        {
            OnLogReceived($"Exception: {value}");

            ExceptionOccurred?.Invoke(this, value);
        }

        private void OnLogReceived(string value)
        {
            LogReceived?.Invoke(this, value);
        }

        #endregion

        #region Constructors

        public HVpnService()
        {
            Vpn.LogReceived += (_, message) => OnLogReceived(message);
            Vpn.ExceptionOccurred += (_, exception) => OnExceptionOccurred(exception);
            Vpn.StatusChanged += async (_, args) =>
            {
                try
                {
                    await IpcServer.WriteAsync(new StatusResponse
                    {
                        Status = args,
                    });
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            Vpn.TrafficStatsChanged += async (_, args) =>
            {
                try
                {
                    await IpcServer.SendTrafficStatsAsync(args.bytesIn, args.bytesOut);
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
        }

        #endregion

        #region Methods

        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            OnLogReceived("Starting...");
   
            IpcServer.ExceptionOccurred += (_, exception) => OnExceptionOccurred(exception);
            IpcServer.ClientConnected += (_, args) => OnLogReceived("IPC client connected");
            IpcServer.ClientDisconnected += (_, args) => OnLogReceived("IPC client disconnected");
            IpcServer.MethodCalled += (_, method) => OnLogReceived($"IPC method called: {method.Id} {method.Method}");
            IpcServer.MessageReceived += (_, message) => OnLogReceived($"IPC message received: {message}");
            IpcServer.MessageSent += (_, message) => OnLogReceived($"IPC message sent: {message}");
            IpcServer.ResponseSent += (_, response) => OnLogReceived($"IPC response sent: {response.Id} {response.Response}");
            IpcServer.StartConnectionMethodCalled += async (_, method) =>
            {
                try
                {
                    await Vpn.StartVpnAsync(method.OVpn, method.Username, method.Password);
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.StopConnectionMethodCalled += async (_, method) =>
            {
                try
                {
                    await Vpn.StopVpnAsync();
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.RequestStatusMethodCalled += async (_, method) =>
            {
                try
                {
                    await IpcServer.WriteAsync(new StatusResponse
                    {
                        Id = method.Id,
                        Status = Vpn.Status,
                    });
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.RequestOptionsMethodCalled += async (_, method) =>
            {
                try
                {
                    await IpcServer.SendOptionsAsync(
                        method.Id, 
                        Vpn.FirewallSettings.AllowLan,
                        Vpn.FirewallSettings.EnableKillSwitch);
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.RequestVersionMethodCalled += async (_, method) =>
            {
                try
                {
                    await IpcServer.SendVersionAsync(method.Id, Vpn.GetVersion());
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.ChangeFirewallSettingsMethodCalled += (_, method) =>
            {
                try
                {
                    Vpn.ChangeFirewallSettings(new FirewallSettings
                    {
                        EnableFirewallOnStart = true,
                        AllowLan = method.AllowLan,
                        EnableKillSwitch = method.EnableKillSwitch,
                        LocalIp = method.LocalIp ?? string.Empty,
                        PrimaryDns = method.PrimaryDns ?? string.Empty,
                        SecondaryDns = method.SecondaryDns ?? string.Empty,
                        SplitTunnelingApps = method.SplitTunnelingApps ?? new List<string>(),
                        SplitTunnelingMode = method.SplitTunnelingMode,
                    }, method.VpnIp ?? string.Empty);
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };
            IpcServer.DisableFirewallMethodCalled += (_, method) =>
            {
                try
                {
                    Vpn.StopFirewall();
                }
                catch (Exception exception)
                {
                    OnExceptionOccurred(exception);
                }
            };

            await IpcServer.StartAsync(cancellationToken);

            OnLogReceived("Started");
        }

        public void Stop()
        {
            Dispose();
        }

        public void Dispose()
        {
            IpcServer.Dispose();
            Vpn.Dispose();
        }

        #endregion
    }
}
