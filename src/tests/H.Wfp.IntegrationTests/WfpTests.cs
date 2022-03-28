namespace H.Wfp.Tests;

[TestClass]
public class WfpTests
{
    [TestMethod]
    public void WfpSessionTest()
    {
        using var session = WfpMethods.CreateWfpSession("H.Wfp", "H.Wfp dynamic session");

        var providerGuid = WfpMethods.AddProvider(
            session,
            "H.Wfp",
            "H.Wfp provider");
        WfpMethods.AddSubLayer(
            session,
            providerGuid,
            "H.Wfp filters",
            "Permissive and blocking filters");
    }
}
