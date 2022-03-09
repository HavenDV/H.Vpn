using H.Vpn;

namespace H.VpnService.Models
{
    /// <summary>
    /// service status
    /// </summary>
    public class StatusResponse : RpcResponse
    {
        public StatusResponse()
        {
            Id = 0;
            Response = "status";
        }

        public ServiceStatus Status { get; set; } = new();
    }
}
