namespace H.OpenVpn.Tests;

[TestClass]
public class OpenVpnTests
{
    private const string Config = @"client
dev tun
proto udp
remote melbourne.wevpn.com 1194
resolv-retry 5
nobind
persist-key
persist-tun
remote-cert-tls server
redirect-gateway autolocal
auth SHA512
cipher AES-256-GCM
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
auth-user-pass
explicit-exit-notify 2
route-delay 0

pull-filter ignore ""ping-restart""

keepalive 5 25
reneg-sec 0

connect-retry 10

script-security 2
pull-filter ignore ""dhcp-option DNS""
dhcp-option DNS 10.255.0.1
dhcp-option DOMAIN example.lan


<ca>
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIUPppqnRZfvGGrT4GjXFE4Q29QzgowDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIQ2hhbmdlTWUwHhcNMTkxMTA1MjMzMzIzWhcNMjkxMTAy
MjMzMzIzWjATMREwDwYDVQQDDAhDaGFuZ2VNZTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAL5DFBJlTqhXukJFWlI8TNW9+HEQCZXhyVFvQhJFF2xIGVNx
51XzqxiRANjVJZJrA68kV8az0v2Dxj0SFnRWDR6pOjjdp2CyHFcgHyfv+4MrsreA
tkue86bB/1ECPWaoIwtaLnwI6SEmFZl98RlI9v4M/8IE4chOnMrM/F22+2OXI//T
duvTcbyOMUiiouIP8UG1FB3J5FyuaW6qPZz2G0efDoaOI+E9LSxE87OoFrII7Uqd
HlWxRb3nUuPU1Ee4rN/d4tFyP4AvPKfsGhVOwyGG21IdRnbXIuDi0xytkCGOZ4j2
bq5zqudnp4Izt6yJgdzZpQQWK3kSHB3qTT/Yzl8CAwEAAaOBjTCBijAdBgNVHQ4E
FgQUXYkoo4WbkkvbgLVdGob9RScRf3AwTgYDVR0jBEcwRYAUXYkoo4WbkkvbgLVd
Gob9RScRf3ChF6QVMBMxETAPBgNVBAMMCENoYW5nZU1lghQ+mmqdFl+8YatPgaNc
UThDb1DOCjAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjANBgkqhkiG9w0BAQsF
AAOCAQEAOr1XmyWBRYfTQPNvZZ+DjCfiRYzLOi2AGefZt/jETqPDF8deVbyL1fLh
XZzuX+5Etlsil3PflJjpzc/FSeZRuYRaShtwF3j6I08Eww9rBkaCnsukMUcLtMOv
hdAU8dUakcRA2wkQ7Z+TWdMBv5+/6MnX10An1fIz7bAy3btMEOPTEFLo8Bst1SxJ
tUMaqhUteSOJ1VorpK3CWfOFaXxbJAb4E0+3zt6Vsc8mY5tt6wAi8IqiN4WD79Zd
vKxENK4FMkR1kNpBY97mvdf82rzpwiBuJgN5ywmH78Ghj+9T8nI6/UIqJ1y22IRY
Gv6dMif8fHo5WWhCv3qmCqqY8vwuxw==
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIRAKxt8SMIXezjmHm2KDCAQdIwDQYJKoZIhvcNAQELBQAw
EzERMA8GA1UEAwwIQ2hhbmdlTWUwHhcNMTkxMTA1MjMzMzI0WhcNMjkxMTAyMjMz
MzI0WjAOMQwwCgYDVQQDDAN0Y3AwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCvEwY2erLhMm3Mpsnybm3G6zvGyeblUAaehQVEUs+KM2/5np0Ovx0y8Iz9
pIC9ITaWM0B3dM6uBsNEtylZIe4Dd9aFujunSeCFsLRf8i9AbrUombpQ6P4jzYFB
xwcEw//UShwa4HZI6JuSYikdpx/dyXdBH2skahwDVc8VUFdBLLSglfKGbuzP9Gsd
SwQCeBRWgA3dvIzIkQkBwfnt9WQKUfRAe8e5NybaAn8Yuu9sjLkQe6eyV7toxkZT
cEXdABG2vtdTEzlAsQilZzIxg3jcdeEgMgRKngng+YNP0rR5nofZ1iDlp+vBj0nu
qTTJLHMrRWPIc7bdYFD/f2J49WORAgMBAAGjgZ8wgZwwCQYDVR0TBAIwADAdBgNV
HQ4EFgQUmSAFmCo1FAKVq8RQF7jMxMxcMtUwTgYDVR0jBEcwRYAUXYkoo4Wbkkvb
gLVdGob9RScRf3ChF6QVMBMxETAPBgNVBAMMCENoYW5nZU1lghQ+mmqdFl+8YatP
gaNcUThDb1DOCjATBgNVHSUEDDAKBggrBgEFBQcDAjALBgNVHQ8EBAMCB4AwDQYJ
KoZIhvcNAQELBQADggEBADPqdEgL+0kou8P974QEaNg1XOAXpwP0NNqbkZ/Oj9+L
p96YAhAHOAJig+RWbBktK8zu8oUUGR1qLXAWCmirlXErVuBRnadTEh3A7SOuY02B
csYAtpQ2EU9j5K/LV7nTfagkVdWy7x/av361UD4t9fv1j4YYTh4XLRp7KVXs6AGZ
7T1hqPYFMUIoPpFhPzFxH4euJjfazr4SkTR6k6Vhw3pyFd6HP65vcqpzHGxFytSa
8HtltBk2DpzIf8yV9TEy+gOXFaaGss0YKQ5OU1ieqZRuLVEGiu17lByYiQGyemIE
TJbdkyiSg93dDJRxjaTk7c8CEdpipt07ndSIPldMtXA=
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCvEwY2erLhMm3M
psnybm3G6zvGyeblUAaehQVEUs+KM2/5np0Ovx0y8Iz9pIC9ITaWM0B3dM6uBsNE
tylZIe4Dd9aFujunSeCFsLRf8i9AbrUombpQ6P4jzYFBxwcEw//UShwa4HZI6JuS
Yikdpx/dyXdBH2skahwDVc8VUFdBLLSglfKGbuzP9GsdSwQCeBRWgA3dvIzIkQkB
wfnt9WQKUfRAe8e5NybaAn8Yuu9sjLkQe6eyV7toxkZTcEXdABG2vtdTEzlAsQil
ZzIxg3jcdeEgMgRKngng+YNP0rR5nofZ1iDlp+vBj0nuqTTJLHMrRWPIc7bdYFD/
f2J49WORAgMBAAECggEACp0HomPb1kUdXOu7kGPbadS24f05bytjy1ZbFGJEzKcD
oclY0h0J4x2sHnBLkauiyIZA4T0GjoxAaDkGW63v5Ovt6Ft65FBZOSGWPb7L2Icd
mmF/ZwpI5di+fkNXjJVpO/BmNcbnxNG9JKmovnB0QRjGjv8dmq6IFjesfylIsN2w
RY15iGXm09woXkw9b+OGOmaMOse7BOPBXdwS79pmsH+L9yJx42Wqjl4d2SF/H21W
cIs4dgY/fRtqEXpucuOrabQUat4t959L4cD3c88jto6RKQK6/MAFSxKoKu6c3jFL
mNZBhtvvjXHX5czwZ8d26qDASagoCBMSX2v5Q4tIBQKBgQDXNJ1pDZOJzzceJ8S2
x5R8dWuWzdcv69la4iQyji0IVhkctjBVBPX01gWj0vXfbegx2388pQTAEUB1UAaQ
wnDr4FHH1XZDC03BCpodvFRmPIXNP+EZg0hYl2YFhV1+7bbqqzTkF+2NUHAbQJdL
pKrkCoq5aXa8MXFci02X6kZokwKBgQDQQvEvl/N4ih2duyv7IbKM/psHcI0JDopN
LHmUWKxLR5HL9mPeEBpolvwiQ46IwCzyDDh4oc0Njdj9m/ZwI0AREMW3Ft2JQwfx
YzQZHIw2Rt7kSTkkB8TniRy453e8KeOA83zv7OJ8QDCvxB4C3su+ScuuiHSnqh9h
kypWSIsNywKBgQDK0b6MlIv49D7I/8foTz5E8dD9Jm/orQmDGt/seYw9cA9ovNfe
OLepEM/t7tNkyEtuOaS3vfo1Hc03Ar29TlNoKlhI0ogLdarJBTnsTmLom5+qqcp2
5gCX5c/z4hYUmuqqTcKiOV7bsPSG6p/sXXvlQX4uchPCF4L0KiFtzBChWwKBgQCj
mRKRypHNzOF6+H+SJWR3ccIi0/1Wcf+epCNVr1qZQD19ta250XiNVJ335I3hSuWD
tqndyWylCxq8DnpGmMpJHZ3TN7kLjIZ+zuksGMrkEEQjnImwjhHVuFXBwsLCIz2+
HIe2iaVY6avVRwA0TQRMFPhVwIey9eb05YBKi24AhQKBgQCjYcWROGN2YQ2piqoy
SwQrYyS+zYeVeMk8unGUcisHlL1p2osKMLYO3Kn+roVTYq/TbPGSRCUruIMJvhQK
gng6e2ytH5+No96c9eWJIzpOwSA2aOSEzy4+AKw04H2s9QRHbsYjxTG7qAyh5SOT
yoBPQBY7V+cJVtXVvXHbaiXK9w==
-----END PRIVATE KEY-----
</key>

<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
7be66c0df0b8855e076d9e37b19f9ff3
c1735ed537dee6dc786e51bdb8502f87
8077eeba0420a25e2b04814d22bbdcc0
191a4fc396fdba1af6eb090a9d8664f1
8e70012ee98a2e32c28620a771d13cf3
a619c417480c2c312562fffaebfd7ba7
3f57a28edde6c287365e6ce28291a297
28da211cb53e01aa46b92f5f276c61fb
46bd810b41219022c8f3d9e699fe9ade
6bfcbb937fbbf6f49d741740e71c7c00
8a9a13c2432608038c6310b4f33588d8
d234b3dffcf0823395267d73140d0e9a
40e323ca92866c37073bfb072ab9de51
8bb9f2c65df7e219c2f114afbcf7c6e3
c401cb08c3ed2901725b0601d2b5de89
245719dd32506d52f149d14156215c1e
-----END OpenVPN Static key V1-----
</tls-crypt>";
    private const string Username = "a0d6ee2a-9b9f-44d1-a349-67f184b2ad32";
    private const string Password = "71k9vkc4JW";

    [TestMethod]
    public void StartTest()
    {
        using var vpn = new HOpenVpn();
        vpn.Start(Config, Username, Password);
    }

    [TestMethod]
    public async Task SendSignalTest()
    {
        using var vpn = new HOpenVpn();
        vpn.Start(Config, Username, Password);

        await vpn.WaitAuthenticationAsync();
        await vpn.SendSignalAsync(Signal.SIGTERM);
        vpn.ConsoleLineReceived += (_, message) =>
        {
            File.AppendAllText("log.txt", message + Environment.NewLine);
        };
        vpn.ManagementLineReceived += (_, message) =>
        {
            File.AppendAllText("log.txt", message + Environment.NewLine);
        };
    }

    [TestMethod]
    public async Task GetPidTest()
    {
        using var vpn = new HOpenVpn();
        vpn.Start(Config, Username, Password);

        await vpn.WaitAuthenticationAsync();

        vpn.ConsoleLineReceived += (_, message) =>
        {
            File.AppendAllText("log.txt", message + Environment.NewLine);
        };
        vpn.ManagementLineReceived += (_, message) =>
        {
            File.AppendAllText("log.txt", message + Environment.NewLine);
        };
        var pid = await vpn.GetPidAsync();
        Assert.AreNotEqual(pid, 0);
    }

    [TestMethod]
    public async Task GetStatesTest()
    {
        using var vpn = new HOpenVpn();
        vpn.Start(Config, Username, Password);

        await vpn.WaitAuthenticationAsync();

        var _ = await vpn.GetStatesAsync();
    }

    [TestMethod]
    public async Task GetLogsTest()
    {
        using var vpn = new HOpenVpn();
        vpn.Start(Config, Username, Password);

        await vpn.WaitAuthenticationAsync();

        var _ = await vpn.GetLogsAsync();
    }
}
