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
NOTE: To use this code in your application, you must either run it as an administrator or 
run it through a service talking to it via IPC (eg [H.Pipes](https://github.com/HavenDV/H.Pipes)).
Else you will get the following error: `0x8032000D. The call must be made from within an explicit transaction.`
```cs
using var firewall = new FirewallBuilder()
    .Block()
    .All()
    .Allow()
    .Localhost()
    .DomainNameSystem()
    .LocalAreaNetwork()
    .Application(@"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe")
    .Build();

await Task.Delay(TimeSpan.FromSeconds(15));
```

H.Firewall uses [WFP](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) calls internally, 
you can learn more about this.

### Links
- [Introduction to the Windows Filtering Platform](https://scorpiosoftware.net/2022/12/25/introduction-to-the-windows-filtering-platform/]
- [WFPExplorer](https://github.com/zodiacon/WFPExplorer)

### Contacts
* [mail](mailto:havendv@gmail.com)