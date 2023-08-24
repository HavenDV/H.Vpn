namespace H.Firewall;

internal enum ConditionType
{
    All,
    Localhost,
    LocalAreaNetwork,
    DomainNameSystem,
    Application,
    IpAddress,
    InternetKeyExchangeVersion2,
    TcpPort,
    UdpPort,
    LocalSubNetwork,
    RemoteSubNetwork,
    NetworkInterface,
}