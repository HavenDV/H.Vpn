## H.Vpn
A set of C# libraries for VPN implementation

### Features
- Supports firewall that will block the internet if there are connection problems.
- Based on OpenVPN

### Nuget

[![NuGet](https://img.shields.io/nuget/dt/H.Wfp.svg?style=flat-square&label=H.Wfp)](https://www.nuget.org/packages/H.Wfp/)  
[![NuGet](https://img.shields.io/nuget/dt/H.IpHlpApi.svg?style=flat-square&label=H.IpHlpApi)](https://www.nuget.org/packages/H.IpHlpApi/)  
[![NuGet](https://img.shields.io/nuget/dt/H.Firewall.svg?style=flat-square&label=H.Firewall)](https://www.nuget.org/packages/H.Firewall/)  
[![NuGet](https://img.shields.io/nuget/dt/H.OpenVpn.svg?style=flat-square&label=H.OpenVpn)](https://www.nuget.org/packages/H.OpenVpn/)  
[![NuGet](https://img.shields.io/nuget/dt/H.Vpn.svg?style=flat-square&label=H.Vpn)](https://www.nuget.org/packages/H.Vpn/)  


## Usage
### H.Firewall
Forbids for 15 seconds everything except LAN/DNS/Localhost requests and Chrome applications.  
NOTE: The application that runs this must have administrator rights.  
Else you will get the following error: `0x8032000D. The call must be made from within an explicit transaction.`
```cs
using var firewall = new HFirewall();

firewall.Start();
firewall.RunTransaction(ptr =>
{
    var (providerKey, subLayerKey) = firewall.RegisterKeys();
    firewall.PermitAppId(
        providerKey,
        subLayerKey,
        @"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe",
        15);

    firewall.PermitLan(providerKey, subLayerKey, 12);
    firewall.PermitDns(providerKey, subLayerKey, 11, 10);
    firewall.PermitLocalhost(providerKey, subLayerKey, 1);

    // Block everything not allowed explicitly
    firewall.BlockAll(providerKey, subLayerKey, 0);
});

await Task.Delay(TimeSpan.FromSeconds(15));
```

### Usage

### Contacts
* [mail](mailto:havendv@gmail.com)