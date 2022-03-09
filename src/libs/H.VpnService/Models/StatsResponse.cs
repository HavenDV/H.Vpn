using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// connection stats
    /// </summary>
    public class StatsResponse : RpcResponse
    {
        public StatsResponse()
        {
            Id = 0;
            Response = "stats";
        }

        [JsonProperty("bytesIn", Required = Required.Always)]
        public long BytesIn { get; set; }

        [JsonProperty("bytesOut", Required = Required.Always)]
        public long BytesOut { get; set; }
    }
}
