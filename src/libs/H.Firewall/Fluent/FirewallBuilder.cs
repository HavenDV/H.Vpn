using System.Net;
using System.Runtime.Versioning;
using H.Wfp.Interop;

namespace H.Firewall;

[SupportedOSPlatform("windows6.0.6000")]
public class FirewallBuilder
{
    private FWP_ACTION_TYPE CurrentAction { get; set; } = FWP_ACTION_TYPE.FWP_ACTION_BLOCK;

    private List<Condition> Conditions { get; } = new();

    /// <summary>
    /// Specifies that everything following will be blocked.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Block()
    {
        CurrentAction = FWP_ACTION_TYPE.FWP_ACTION_BLOCK;
        return this;
    } 

    /// <summary>
    /// Specifies that everything following will be allowed.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Allow()
    {
        CurrentAction = FWP_ACTION_TYPE.FWP_ACTION_PERMIT;
        return this;
    }
    
    /// <summary>
    /// Blocks/allows connections to the current computer.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Localhost()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.Localhost,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder All()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.All,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all LAN connections.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder LocalAreaNetwork()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.LocalAreaNetwork,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all DNS connections.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder DomainNameSystem()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.DomainNameSystem,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections of specific application.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Application(params string[] paths)
    {
        paths = paths ?? throw new ArgumentNullException(nameof(paths));
        
        foreach (var path in paths)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.Application,
                Path = path,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified URI.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Uri(params Uri[] uris)
    {
        uris = uris ?? throw new ArgumentNullException(nameof(uris));
        
        foreach (var uri in uris)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.Uri,
                Uri = uri,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified IP address.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder IpAddress(params IPAddress[] addresses)
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.IpAddress,
            Addresses = addresses,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to IKEv2.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder InternetKeyExchangeVersion2()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.InternetKeyExchangeVersion2,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections uses specified TCP port.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder TcpPortV4(params ushort[] ports)
    {
        ports = ports ?? throw new ArgumentNullException(nameof(ports));
        
        foreach (var port in ports)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.TcpPortV4,
                Port = port,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections uses specified UDP port.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder UdpPortV4(params ushort[] ports)
    {
        ports = ports ?? throw new ArgumentNullException(nameof(ports));
        
        foreach (var port in ports)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.UdpPortV4,
                Port = port,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified local sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder LocalSubNetworkV4(params IPNetwork[] networks)
    {
        networks = networks ?? throw new ArgumentNullException(nameof(networks));
        
        foreach (var network in networks)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.LocalSubNetworkV4,
                Network = network,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified remote sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder RemoteSubNetworkV4(params IPNetwork[] networks)
    {
        networks = networks ?? throw new ArgumentNullException(nameof(networks));
        
        foreach (var network in networks)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.RemoteSubNetworkV4,
                Network = network,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified network interface.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder NetworkInterface(params ulong[] indexes)
    {
        indexes = indexes ?? throw new ArgumentNullException(nameof(indexes));
        
        foreach (var index in indexes)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Type = ConditionType.NetworkInterface,
                InterfaceIndex = index,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Creates and launches a firewall. You must call <see cref="HFirewall.Dispose"/> after the end.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public HFirewall Build()
    {
        var firewall = new HFirewall();

        firewall.Start();
        firewall.RunTransaction(handle =>
        {
            byte weight = 0;
            var (providerKey, subLayerKey) = handle.RegisterKeys();

            foreach (var condition in Conditions)
            {
                switch (condition.Type, condition.Action)
                {
                    case (ConditionType.All, FWP_ACTION_TYPE.FWP_ACTION_BLOCK):
                        handle.BlockAll(providerKey, subLayerKey, weight++);
                        break;
                    case (ConditionType.Localhost, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitLocalhost(providerKey, subLayerKey, weight++);
                        break;
                    case (ConditionType.LocalAreaNetwork, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitLan(providerKey, subLayerKey, weight++);
                        break;
                    case (ConditionType.DomainNameSystem, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        var weightDeny = weight++;
                        var weightAllow = weight++;
                        handle.PermitDns(providerKey, subLayerKey, weightAllow, weightDeny);
                        break;
                    case (ConditionType.Application, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitAppId(
                            providerKey,
                            subLayerKey,
                            condition.Path,
                            weight++);
                        break;
                    case (ConditionType.Uri, FWP_ACTION_TYPE.FWP_ACTION_BLOCK):
                        handle.BlockUri(
                            providerKey,
                            subLayerKey,
                            weight++,
                            condition.Uri);
                        break;
                    case (ConditionType.Uri, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitUri(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            condition.Uri);
                        break;
                    case (ConditionType.IpAddress, FWP_ACTION_TYPE.FWP_ACTION_BLOCK):
                        handle.BlockIpAddresses(
                            providerKey,
                            subLayerKey,
                            weight++,
                            condition.Addresses);
                        break;
                    case (ConditionType.IpAddress, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitIpAddresses(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            condition.Addresses);
                        break;
                    case (ConditionType.InternetKeyExchangeVersion2, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitIKEv2(
                            providerKey,
                            subLayerKey,
                            weight: weight++);
                        break;
                    case (ConditionType.TcpPortV4, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitTcpPortV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            port: condition.Port);
                        break;
                    case (ConditionType.UdpPortV4, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitUdpPortV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            port: condition.Port);
                        break;
                    case (ConditionType.LocalSubNetworkV4, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitLocalSubNetworkV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            network: condition.Network);
                        break;
                    case (ConditionType.RemoteSubNetworkV4, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitRemoteSubNetworkV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            network: condition.Network);
                        break;
                    case (ConditionType.NetworkInterface, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitNetworkInterface(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            ifLuid: condition.InterfaceIndex);
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        });

        return firewall;
    }
}