using Newtonsoft.Json;

namespace H.VpnService.Models
{
    /// <summary>
    /// service version
    /// </summary>
    public class VersionResponse : RpcResponse
    {
        public VersionResponse()
        {
            Id = 0;
            Response = "version";
        }

        [JsonProperty("name", Required = Required.Always)]
        public string? Name { get; set; }

        [JsonProperty("identifier", Required = Required.Always)]
        public string? Identifier { get; set; }

        [JsonProperty("description", Required = Required.Always)]
        public string? Description { get; set; }

        [JsonProperty("version", Required = Required.Always)]
        public string? Version { get; set; }
    }
}
