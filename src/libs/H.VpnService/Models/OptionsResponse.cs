using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// service options
    /// </summary>
    public class OptionsResponse : RpcResponse
    {
        public OptionsResponse()
        {
            Id = 0;
            Response = "options";
        }

        [JsonProperty("isKillSwitchEnabled", Required = Required.Always)]
        public bool IsKillSwitchEnabled { get; set; }

        [JsonProperty("allowLAN", Required = Required.Always)]
        public bool AllowLan { get; set; }
    }
}
