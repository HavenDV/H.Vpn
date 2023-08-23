using System.Runtime.InteropServices;

namespace H.Firewall.Tests;

[TestClass]
public class WfpTests
{
    [TestMethod]
    public void HFirewallTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();
        _ = firewall.WfpSession.RegisterKeys();
    }

    [TestMethod]
    public async Task AllowOnlyChromeLanDnsAndLocalhostTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();
        firewall.RunTransaction(handle =>
        {
            var (providerKey, subLayerKey) = handle.RegisterKeys();
            handle.PermitAppId(
                providerKey,
                subLayerKey,
                @"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe",
                15);

            handle.PermitLan(providerKey, subLayerKey, 12);
            handle.PermitDns(providerKey, subLayerKey, 11, 10);
            handle.PermitLocalhost(providerKey, subLayerKey, 1);

            // Block everything not allowed explicitly
            handle.BlockAll(providerKey, subLayerKey, 0);
        });

        await Task.Delay(TimeSpan.FromSeconds(15));
    }

    [TestMethod]
    public async Task AllowOnlyChromeLanDnsAndLocalhostTestBuilder()
    {
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
    }

    [TestMethod]
    public void GetAppIdFromFileNameTest()
    {
        using (SessionExtensions.GetAppId(@"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe"))
        {
        }
    }

    [TestMethod]
    public void WfpSessionNotOpenDisposeTest()
    {
        using (new HFirewall())
        {
        }
    }

    [TestMethod]
    public void WfpSessionNotOpenRunTransactionTest()
    {
        Assert.ThrowsException<COMException>(() =>
        {
            using var firewall = new HFirewall();
            firewall.RunTransaction(_ => { });
        });
    }
}