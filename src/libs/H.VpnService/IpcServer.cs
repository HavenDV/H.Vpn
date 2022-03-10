using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using H.Pipes;
using H.Pipes.AccessControl;
using Newtonsoft.Json;
using H.VpnService.Models;

namespace H.VpnService;

public class IpcServer : IDisposable
{
    #region Properties

    private IPipeServer<string> PipeServer { get; } = new SingleConnectionPipeServer<string>(nameof(H.VpnService));

    #endregion

    #region Events

    public event EventHandler<Exception>? ExceptionOccurred;

    public event EventHandler<RpcMethod>? MethodCalled;
    public event EventHandler<string>? ClientConnected;
    public event EventHandler<string>? ClientDisconnected;
    public event EventHandler<string>? MessageReceived;

    public event EventHandler<RpcResponse>? ResponseSent;
    public event EventHandler<string>? MessageSent;

    public event EventHandler<StartConnectionMethod>? StartConnectionMethodCalled;
    public event EventHandler<StopConnectionMethod>? StopConnectionMethodCalled;
    public event EventHandler<RequestStatusMethod>? RequestStatusMethodCalled;
    public event EventHandler<RequestOptionsMethod>? RequestOptionsMethodCalled;
    public event EventHandler<RequestVersionMethod>? RequestVersionMethodCalled;
    public event EventHandler<ChangeFirewallSettingsMethod>? ChangeFirewallSettingsMethodCalled;
    public event EventHandler<DisableFirewallMethod>? DisableFirewallMethodCalled;
    public event EventHandler<RpcMethod>? SignOutMethodCalled;

    private void OnMethodCalled(RpcMethod value)
    {
        MethodCalled?.Invoke(this, value);
    }

    private void OnResponseSent(RpcResponse value)
    {
        ResponseSent?.Invoke(this, value);
    }

    private void OnExceptionOccurred(Exception value)
    {
        ExceptionOccurred?.Invoke(this, value);
    }

    private void OnClientConnected(string value)
    {
        ClientConnected?.Invoke(this, value);
    }

    private void OnClientDisconnected(string value)
    {
        ClientDisconnected?.Invoke(this, value);
    }

    private void OnMessageReceived(string value)
    {
        MessageReceived?.Invoke(this, value);
    }

    private void OnMessageSent(string value)
    {
        MessageSent?.Invoke(this, value);
    }

    private void OnStartConnectionMethodCalled(StartConnectionMethod value)
    {
        StartConnectionMethodCalled?.Invoke(this, value);
    }

    private void OnStopConnectionMethodCalled(StopConnectionMethod value)
    {
        StopConnectionMethodCalled?.Invoke(this, value);
    }

    private void OnRequestStatusMethodCalled(RequestStatusMethod value)
    {
        RequestStatusMethodCalled?.Invoke(this, value);
    }

    private void OnRequestOptionsMethodCalled(RequestOptionsMethod value)
    {
        RequestOptionsMethodCalled?.Invoke(this, value);
    }

    private void OnRequestVersionMethodCalled(RequestVersionMethod value)
    {
        RequestVersionMethodCalled?.Invoke(this, value);
    }

    private void OnChangeFirewallSettingsMethodCalled(ChangeFirewallSettingsMethod value)
    {
        ChangeFirewallSettingsMethodCalled?.Invoke(this, value);
    }

    private void OnDisableFirewallMethodCalled(DisableFirewallMethod value)
    {
        DisableFirewallMethodCalled?.Invoke(this, value);
    }

    private void OnSignOutMethodCalled(RpcMethod value)
    {
        SignOutMethodCalled?.Invoke(this, value);
    }

    #endregion

    #region Methods

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        PipeServer.AddAccessRules(
            new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

        PipeServer.ExceptionOccurred += (_, args) => OnExceptionOccurred(args.Exception);
        PipeServer.ClientConnected += (_, args) => OnClientConnected("Pipe client connected");
        PipeServer.ClientDisconnected += (_, args) => OnClientDisconnected("Pipe client connected");
        PipeServer.MessageReceived += (_, args) =>
        {
            try
            {
                OnMessageReceived(args.Message);

                var json = args.Message;
                var method = JsonConvert.DeserializeObject<RpcMethod>(json);

                OnMethodCalled(method);
                switch (method.Method)
                {
                    case "startConnection":
                        var startConnection = JsonConvert.DeserializeObject<StartConnectionMethod>(json);
                        OnStartConnectionMethodCalled(startConnection);
                        break;

                    case "stopConnection":
                        var stopConnection = JsonConvert.DeserializeObject<StopConnectionMethod>(json);
                        OnStopConnectionMethodCalled(stopConnection);
                        break;

                    case "requestStatus":
                        var requestStatus = JsonConvert.DeserializeObject<RequestStatusMethod>(json);
                        OnRequestStatusMethodCalled(requestStatus);
                        break;

                    case "requestOptions":
                        var requestOptions = JsonConvert.DeserializeObject<RequestOptionsMethod>(json);
                        OnRequestOptionsMethodCalled(requestOptions);
                        break;

                    case "requestVersion":
                        var requestVersion = JsonConvert.DeserializeObject<RequestVersionMethod>(json);
                        OnRequestVersionMethodCalled(requestVersion);
                        break;

                    case "changeFirewallSettings":
                        var changeFirewallSettings = JsonConvert.DeserializeObject<ChangeFirewallSettingsMethod>(json);
                        OnChangeFirewallSettingsMethodCalled(changeFirewallSettings);
                        break;

                    case "disableFirewall":
                        var disableFirewall = JsonConvert.DeserializeObject<DisableFirewallMethod>(json);
                        OnDisableFirewallMethodCalled(disableFirewall);
                        break;

                    case "signOut":
                        OnSignOutMethodCalled(method);
                        break;
                }
            }
            catch (Exception exception)
            {
                OnExceptionOccurred(exception);
            }
        };

        await PipeServer.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteAsync(RpcResponse response, CancellationToken cancellationToken = default)
    {
        var json = JsonConvert.SerializeObject(new[] {response});

        await PipeServer.WriteAsync(json, cancellationToken).ConfigureAwait(false);

        OnMessageSent(json);
        OnResponseSent(response);
    }

    public async Task SendLogAsync(string text, CancellationToken cancellationToken = default)
    {
        await WriteAsync(new LogResponse
        {
            Text = text,
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SendTrafficStatsAsync(long bytesIn, long bytesOut, CancellationToken cancellationToken = default)
    {
        await WriteAsync(new StatsResponse
        {
            BytesIn = bytesIn,
            BytesOut = bytesOut,
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SendOptionsAsync(
        int id, 
        bool allowLan, 
        bool isKillSwitchEnabled, 
        CancellationToken cancellationToken = default)
    {
        await WriteAsync(new OptionsResponse
        {
            Id = id,
            AllowLan = allowLan,
            IsKillSwitchEnabled = isKillSwitchEnabled,
        }, cancellationToken).ConfigureAwait(false);
    }

    public async Task SendVersionAsync(
        int id,
        Version version,
        CancellationToken cancellationToken = default)
    {
        await WriteAsync(new VersionResponse
        {
            Id = id,
            Name = "H.VpnService",
            Identifier = "com.H.VpnService.v1.desktop.service",
            Description = $"H.VpnService service for VPN connections (v{version})",
            Version = $"v{version}",
        }, cancellationToken).ConfigureAwait(false);
    }

    public void Stop()
    {
        Dispose();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            PipeServer.Dispose();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    #endregion
}
