using System.Net;
using System.Runtime.Versioning;
using H.Wfp.Interop;

namespace H.Firewall;

[SupportedOSPlatform("windows6.0.6000")]
public class FirewallBuilder
{
    private FWP_ACTION_TYPE CurrentAction { get; set; } = FWP_ACTION_TYPE.FWP_ACTION_BLOCK;

    private List<Condition> Conditions { get; } = new();

    private enum ConditionType
    {
        All,
        Localhost,
        LocalAreaNetwork,
        DomainNameSystem,
        Application,
        Uri,
        IpAddress,
    }
    
    private sealed class Condition
    {
        public FWP_ACTION_TYPE Action { get; set; }
        public ConditionType Type { get; set; }
        public string Path { get; set; } = string.Empty;
        public Uri Uri { get; set; } = new("http://localhost/");
        public IPAddress IpAddress { get; set; } = IPAddress.None;
    }
    
    public FirewallBuilder Block()
    {
        CurrentAction = FWP_ACTION_TYPE.FWP_ACTION_BLOCK;
        return this;
    } 

    public FirewallBuilder Allow()
    {
        CurrentAction = FWP_ACTION_TYPE.FWP_ACTION_PERMIT;
        return this;
    }
    
    public FirewallBuilder Localhost()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.Localhost,
        });
        
        return this;
    }
    
    public FirewallBuilder All()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.All,
        });
        
        return this;
    }
    
    public FirewallBuilder LocalAreaNetwork()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.LocalAreaNetwork,
        });
        
        return this;
    }
    
    public FirewallBuilder DomainNameSystem()
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.DomainNameSystem,
        });
        
        return this;
    }
    
    public FirewallBuilder Application(string path)
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.Application,
            Path = path,
        });
        
        return this;
    }
    
    public FirewallBuilder Uri(Uri uri)
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.Uri,
            Uri = uri,
        });
        
        return this;
    }
    
    public FirewallBuilder IpAddress(IPAddress address)
    {
        Conditions.Add(new Condition
        {
            Action = CurrentAction,
            Type = ConditionType.IpAddress,
            IpAddress = address,
        });
        
        return this;
    }
    
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
                            new []{ condition.IpAddress });
                        break;
                    case (ConditionType.IpAddress, FWP_ACTION_TYPE.FWP_ACTION_PERMIT):
                        handle.PermitIpAddresses(
                            providerKey,
                            subLayerKey,
                            weight: weight++,
                            new []{ condition.IpAddress });
                        break;
                    default:
                        throw new NotImplementedException();
                }
            }
        });

        return firewall;
    }
}