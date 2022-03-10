namespace H.Firewall;

public class FirewallSettings
{
    #region Properties

    public bool EnableFirewallOnStart { get; set; }
    public bool EnableKillSwitch { get; set; }
    public bool AllowLan { get; set; } = true;
    public string PrimaryDns { get; set; } = string.Empty;
    public string SecondaryDns { get; set; } = string.Empty;
    public SplitTunnelingMode SplitTunnelingMode { get; set; } = SplitTunnelingMode.Off;
    public ICollection<string> SplitTunnelingApps { get; set; } = new List<string>();
    public string LocalIp { get; set; } = string.Empty;

    #endregion

    #region Methods

    public bool Equals(FirewallSettings other)
    {
        return
            EnableFirewallOnStart == other.EnableFirewallOnStart &&
            EnableKillSwitch == other.EnableKillSwitch &&
            AllowLan == other.AllowLan &&
            PrimaryDns == other.PrimaryDns &&
            SecondaryDns == other.SecondaryDns &&
            SplitTunnelingMode == other.SplitTunnelingMode &&
            string.Equals(
                string.Concat(SplitTunnelingApps),
                string.Concat(other.SplitTunnelingApps),
                StringComparison.Ordinal) &&
            LocalIp == other.LocalIp;
    }

    #endregion
}
