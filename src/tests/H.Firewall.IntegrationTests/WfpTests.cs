namespace H.Firewall.Tests;

[TestClass]
public class WfpTests
{
    [TestMethod]
    public void HFirewallTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();
        firewall.RegisterKeys();
    }

    [TestMethod]
    public void ChangeSettingsTest()
    {
        using var firewall = new HFirewall();

        firewall.ChangeSettings(new Settings
        {
            EnableFirewallOnStart = true,
            EnableKillSwitch = false,
            AllowLan = true,
            PrimaryDns = "10.255.0.1",
            SecondaryDns = string.Empty,
            SplitTunnelingMode = SplitTunnelingMode.Off,
            SplitTunnelingApps = new List<string>(),
            LocalIp = "192.168.1.33",
        }, string.Empty);
    }

    [TestMethod]
    public async Task ChangeSettingsKillSwitchTest()
    {
        using var firewall = new HFirewall();

        firewall.ChangeSettings(new Settings
        {
            EnableFirewallOnStart = true,
            EnableKillSwitch = true,
            AllowLan = true,
            PrimaryDns = "10.255.0.1",
            SecondaryDns = string.Empty,
            SplitTunnelingMode = SplitTunnelingMode.Off,
            SplitTunnelingApps = new List<string>(),
            LocalIp = "192.168.1.33",
        }, string.Empty);

        await Task.Delay(TimeSpan.FromSeconds(15));
    }

    // ReSharper disable AccessToDisposedClosure
    [TestMethod]
    public void PermitAppIdTest()
    {
        using var firewall = new HFirewall();

        firewall.Start();

        firewall.RunTransaction(ptr =>
        {
            var keys = firewall.RegisterKeys();

            firewall.PermitAppId(keys, @"C:\Program Files\H.Wfp\H.Wfp\Service\H.Wfp.Service.exe", 15);
            firewall.PermitAppId(keys, @"C:\Program Files\H.Wfp\H.Wfp\Service\OpenVPN\openvpn.exe", 14);
            firewall.PermitAppId(keys, @"C:\Program Files\H.Wfp\H.Wfp\H.Wfp.exe", 13);
        });
    }

    [TestMethod]
    public void GetAppIdFromFileNameTest()
    {
        using (HFirewall.GetAppId(@"C:\Program Files\H.Wfp\H.Wfp.exe"))
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
        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            using var firewall = new HFirewall();
            firewall.RunTransaction(ptr => { });
        });
    }
}
