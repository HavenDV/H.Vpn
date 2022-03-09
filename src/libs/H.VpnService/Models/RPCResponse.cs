using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// rpc response
    /// </summary>
    public class RpcResponse
    {
        [JsonProperty("id", Required = Required.Always)]
        public int Id { get; set; }

        [JsonProperty("response", Required = Required.Always)]
        public string? Response { get; set; }
    }
}
