using System.Collections.Generic;
using H.Firewall;
using H.Wfp;
using Newtonsoft.Json;

namespace H.VpnService.Models;

/// <summary>
/// change firewall settings
/// </summary>
public class ChangeFirewallSettingsMethod : RpcMethod
{
    [JsonProperty("enableKillSwitch", Required = Required.Always)]
    public bool EnableKillSwitch { get; set; }

    [JsonProperty("allowLan", Required = Required.Always)]
    public bool AllowLan { get; set; }

    [JsonProperty("primaryDNS")]
    public string? PrimaryDns { get; set; }

    [JsonProperty("secondaryDNS")]
    public string? SecondaryDns { get; set; }

    [JsonProperty("splitTunnelingMode")]
    public SplitTunnelingMode SplitTunnelingMode { get; set; }

    [JsonProperty("splitTunnelingApps", Required = Required.Always)]
    public IReadOnlyCollection<string>? SplitTunnelingApps { get; set; }

    [JsonProperty("localIP", Required = Required.Always)]
    public string? LocalIp { get; set; }

    [JsonProperty("vpnIP")]
    public string? VpnIp { get; set; }
}
