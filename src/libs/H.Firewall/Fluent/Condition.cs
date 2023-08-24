using System.Net;
using H.Wfp.Interop;

namespace H.Firewall;

internal sealed class Condition
{
    public FWP_ACTION_TYPE Action { get; set; }
    public ConditionType Type { get; set; }
    public InternetProtocolVersion Version { get; set; } = InternetProtocolVersion.All;
    
    public string Path { get; set; } = string.Empty;
    public Uri Uri { get; set; } = new("http://localhost/");
    public IReadOnlyCollection<IPAddress> Addresses { get; set; } = Array.Empty<IPAddress>();
    public IPNetwork Network { get; set; } = IPNetwork.IANA_ABLK_RESERVED1;
    public ulong InterfaceIndex { get; set; }
    public ushort Port { get; set; }
}