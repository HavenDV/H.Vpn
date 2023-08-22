using System.Globalization;

namespace H.OpenVpn;

public class State
{
    #region Static methods

    public static State Parse(string line)
    {
        line = line ?? throw new ArgumentNullException(nameof(line));

        var values = line.Split(',');

        return new State(
            new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(int.Parse(values[0], CultureInfo.InvariantCulture)),
            values[1].Trim(' '),
            values[2].Trim(' '),
            values[3].Trim(' '),
            values[4].Trim(' ')
        );
    }

    #endregion

    #region Properties

    public DateTime Time { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
    public string LocalIp { get; set; }
    public string RemoteIp { get; set; }

    #endregion

    #region Constructors

    public State(DateTime time, string name, string description, string localIp, string remoteIp)
    {
        Time = time;
        Name = name;
        Description = description;
        LocalIp = localIp;
        RemoteIp = remoteIp;
    }

    #endregion
}
