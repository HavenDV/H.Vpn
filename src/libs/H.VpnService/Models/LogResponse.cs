using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// connection log line
    /// </summary>
    public class LogResponse : RpcResponse
    {
        public LogResponse()
        {
            Id = 0;
            Response = "log";
        }

        [JsonProperty("text", Required = Required.Always)]
        public string? Text { get; set; }
    }
}
