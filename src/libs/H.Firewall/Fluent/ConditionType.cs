namespace H.Firewall;

internal enum ConditionType
{
    All,
    Localhost,
    LocalAreaNetwork,
    DomainNameSystem,
    Application,
    Uri,
    IpAddress,
    InternetKeyExchangeVersion2,
    TcpPortV4,
    UdpPortV4,
    LocalSubNetworkV4,
    RemoteSubNetworkV4,
    NetworkInterface,
}