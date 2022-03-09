namespace H.IpHlpApi.Tests;

[TestClass]
public class NetworkMethodsTests
{
    [TestMethod]
    public void GetLocalIpV4Test()
    {
        foreach (var ip in NetworkMethods.GetLocalIpsV4())
        {
            Console.WriteLine($"LocalIpV: {ip}");

            var tuple = NetworkMethods.FindInterfaceIndexAndMetricByIp(ip);
            Console.WriteLine($"InterfaceIndex: {tuple.Item1}");
            Console.WriteLine($"Metric: {tuple.Item2}");
        }
    }

    [TestMethod]
    public void FindTapAdapterLuidTest()
    {
        Console.WriteLine($"TapAdapterLuid: {NetworkMethods.FindTapAdapterLuid()}");
    }
}
