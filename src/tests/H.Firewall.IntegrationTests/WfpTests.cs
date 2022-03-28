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
        _ = firewall.RegisterKeys();
    }

    [TestMethod]
    public async Task AllowOnlyChromeLanDnsAndLocalhostTest()
    {
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
    }

    [TestMethod]
    public void GetAppIdFromFileNameTest()
    {
        using (HFirewall.GetAppId(@"C:\Users\haven\AppData\Local\Google\Chrome\Application\chrome.exe"))
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
            firewall.RunTransaction(ptr => { });
        });
    }
}
