using System.Runtime.Versioning;

namespace H.Firewall;

[SupportedOSPlatform("windows6.0.6000")]
public static class Layers
{
    public static IReadOnlyDictionary<string, Guid> V4 { get; } = new Dictionary<string, Guid>
    {
        { "IPv4 outbound", PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V4 },
        { "IPv4 inbound", PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
    };

    public static IReadOnlyDictionary<string, Guid> V6 { get; } = new Dictionary<string, Guid>
    {
        { "IPv6 outbound", PInvoke.FWPM_LAYER_ALE_AUTH_CONNECT_V6 },
        { "IPv6 inbound", PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 },
    };

    public static IReadOnlyDictionary<string, Guid> V4Port { get; } = new Dictionary<string, Guid>
    {
        { "IPv4 inbound", PInvoke.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 },
        { "IPv4 established", PInvoke.FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 },
    };
    
    public static IReadOnlyDictionary<string, Guid> All => V4
        .Concat(V6)
        .ToDictionary(pair => pair.Key, pair => pair.Value);
}