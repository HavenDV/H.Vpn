namespace H.OpenVpn;

public enum Signal
{
    /// <summary>
    /// Hard restart.
    /// </summary>
    SIGHUP = 0x1,

    /// <summary>
    /// Conditional restart, designed to restart without root privileges.
    /// </summary>
    SIGUSR1 = 0xa,

    /// <summary>
    /// Output connection statistics to log file or syslog.
    /// </summary>
    SIGUSR2 = 0xc,

    /// <summary>
    /// Exit.
    /// </summary>
    SIGTERM = 0xf
}
