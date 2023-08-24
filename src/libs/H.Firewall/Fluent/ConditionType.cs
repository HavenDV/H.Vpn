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
    TcpPort,
    UdpPort,
    LocalSubNetwork,
    RemoteSubNetwork,
    NetworkInterface,
}