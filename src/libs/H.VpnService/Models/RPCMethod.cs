using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// rpc method
    /// </summary>
    public class RpcMethod
    {
        [JsonProperty("id", Required = Required.Always)]
        public int Id { get; set; }

        [JsonProperty("method", Required = Required.Always)]
        public string? Method { get; set; }
    }
}
