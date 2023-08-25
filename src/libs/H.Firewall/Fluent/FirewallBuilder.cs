using System.Net;
using System.Runtime.Versioning;
using H.Wfp.Interop;

namespace H.Firewall;

/// <summary>
/// The order of the declaration matters. Each subsequent statement has more weight. <br/>
/// By default, all actions apply for both Internet Protocol version 4 and Internet Protocol version 6.
/// </summary>
[SupportedOSPlatform("windows6.0.6000")]
public class FirewallBuilder
{
    private FWP_ACTION_TYPE CurrentAction { get; set; } = FWP_ACTION_TYPE.FWP_ACTION_BLOCK;
    private InternetProtocolVersion CurrentVersion { get; set; } = InternetProtocolVersion.All;

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
    /// Specifies that everything following will be only for IPv4.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder ForInternetProtocolVersion4()
    {
        CurrentVersion = InternetProtocolVersion.Version4;
        return this;
    }

    /// <summary>
    /// Specifies that everything following will be only for IPv6.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder ForInternetProtocolVersion6()
    {
        CurrentVersion = InternetProtocolVersion.Version6;
        return this;
    }

    /// <summary>
    /// Specifies that everything following will be for all IP versions.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder ForAllInternetProtocolVersions()
    {
        CurrentVersion = InternetProtocolVersion.All;
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
            Version = CurrentVersion,
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
            Version = CurrentVersion,
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
            Version = CurrentVersion,
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
            Version = CurrentVersion,
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
                Version = CurrentVersion,
                Type = ConditionType.Application,
                Path = path,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections by peer name.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder PeerName(params Uri[] uris)
    {
        uris = uris ?? throw new ArgumentNullException(nameof(uris));

        foreach (var uri in uris)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Version = CurrentVersion,
                Type = ConditionType.PeerName,
                Uri = uri,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections by peer name.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder PeerName(params string[] urls)
    {
        urls = urls ?? throw new ArgumentNullException(nameof(urls));

        return urls
            .Select(static url => new Uri(url))
            .Aggregate(this, static (builder, addresses) => builder.PeerName(addresses));
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified URI.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Uri(params Uri[] uris)
    {
        uris = uris ?? throw new ArgumentNullException(nameof(uris));

        return uris
            .Select(static uri => Dns.GetHostAddresses(uri.Host))
            .Aggregate(this, static (builder, addresses) => builder.IpAddress(addresses));
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified URL.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder Url(params string[] urls)
    {
        urls = urls ?? throw new ArgumentNullException(nameof(urls));

        return urls
            .Select(static url => new Uri(url))
            .Aggregate(this, static (builder, addresses) => builder.Uri(addresses));
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
            Version = CurrentVersion,
            Type = ConditionType.IpAddress,
            Addresses = addresses,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified IP address.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder IpAddress(params string[] addresses)
    {
        return IpAddress(addresses
            .Select(IPAddress.Parse)
            .ToArray());
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
            Version = CurrentVersion,
            Type = ConditionType.InternetKeyExchangeVersion2,
        });
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections uses specified TCP port.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder TcpPort(params ushort[] ports)
    {
        ports = ports ?? throw new ArgumentNullException(nameof(ports));
        
        foreach (var port in ports)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Version = CurrentVersion,
                Type = ConditionType.TcpPort,
                Port = port,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections uses specified UDP port.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder UdpPort(params ushort[] ports)
    {
        ports = ports ?? throw new ArgumentNullException(nameof(ports));
        
        foreach (var port in ports)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Version = CurrentVersion,
                Type = ConditionType.UdpPort,
                Port = port,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified local sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder LocalSubNetwork(params IPNetwork[] networks)
    {
        networks = networks ?? throw new ArgumentNullException(nameof(networks));
        
        foreach (var network in networks)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Version = CurrentVersion,
                Type = ConditionType.LocalSubNetwork,
                Network = network,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified local sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder LocalSubNetwork(params string[] networks)
    {
        return LocalSubNetwork(networks
            .Select(IPNetwork.Parse)
            .ToArray());
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified remote sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder RemoteSubNetwork(params IPNetwork[] networks)
    {
        networks = networks ?? throw new ArgumentNullException(nameof(networks));
        
        foreach (var network in networks)
        {
            Conditions.Add(new Condition
            {
                Action = CurrentAction,
                Version = CurrentVersion,
                Type = ConditionType.RemoteSubNetwork,
                Network = network,
            });
        }
        
        return this;
    }
    
    /// <summary>
    /// Blocks/allows all connections to specified remote sub network.
    /// </summary>
    /// <returns></returns>
    public FirewallBuilder RemoteSubNetwork(params string[] networks)
    {
        return RemoteSubNetwork(networks
            .Select(IPNetwork.Parse)
            .ToArray());
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
                Version = CurrentVersion,
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
                    case (ConditionType.TcpPort, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitTcpPortV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            port: condition.Port);
                        break;
                    case (ConditionType.UdpPort, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitUdpPortV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            port: condition.Port);
                        break;
                    case (ConditionType.LocalSubNetwork, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitLocalSubNetworkV4(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            network: condition.Network);
                        break;
                    case (ConditionType.RemoteSubNetwork, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
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
                    case (ConditionType.PeerName, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.AddPeerName(
                            FWP_ACTION_TYPE.FWP_ACTION_PERMIT,
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            uri: condition.Uri);
                        break;
                    case (ConditionType.PeerName, FWP_ACTION_TYPE.FWP_ACTION_BLOCK):
                        handle.AddPeerName(
                            FWP_ACTION_TYPE.FWP_ACTION_BLOCK,
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            uri: condition.Uri);
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        });

        return firewall;
    }
}