using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// start VPN connection
    /// </summary>
    public class StartConnectionMethod : RpcMethod
    {
        [JsonProperty("proto", Required = Required.Always)]
        public string? Proto { get; set; }

        [JsonProperty("username", Required = Required.Always)]
        public string? Username { get; set; }

        [JsonProperty("password", Required = Required.Always)]
        public string? Password { get; set; }

        [JsonProperty("ovpn", Required = Required.Always)]
        public string? OVpn { get; set; }
    }
}
