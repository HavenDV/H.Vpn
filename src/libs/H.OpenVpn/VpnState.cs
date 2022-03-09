namespace H.OpenVpn;

public enum VpnState
{
    Inactive,
    Preparing,
    Started,
    Initialized,
    Connecting,
    Restarting,
    Connected,
    Disconnecting,
    DisconnectingToReconnect,
    Exiting,
    Failed,
}