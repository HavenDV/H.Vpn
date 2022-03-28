namespace H.Wfp.Interop;

// ReSharper disable once PartialTypeWithSinglePart
public partial class NativeConstants
{
    public static Guid cFWPM_CONDITION_IP_LOCAL_INTERFACE { get; } = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    public static Guid cFWPM_CONDITION_IP_REMOTE_ADDRESS { get; } = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static Guid cFWPM_CONDITION_IP_PROTOCOL { get; } = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    public static Guid cFWPM_CONDITION_IP_LOCAL_PORT { get; } = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");
    public static Guid cFWPM_CONDITION_IP_REMOTE_PORT { get; } = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    public static Guid cFWPM_CONDITION_ALE_APP_ID { get; } = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    public static Guid cFWPM_CONDITION_ALE_USER_ID { get; } = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");
    public static Guid cFWPM_CONDITION_IP_LOCAL_ADDRESS { get; } = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    public static Guid cFWPM_CONDITION_ICMP_TYPE { get; } = cFWPM_CONDITION_IP_LOCAL_PORT;
    public static Guid cFWPM_CONDITION_ICMP_CODE { get; } = cFWPM_CONDITION_IP_REMOTE_PORT;
    public static Guid cFWPM_CONDITION_L2_FLAGS { get; } = new Guid("7bc43cbf-37ba-45f1-b74a-82ff518eeb10");
    public static Guid FWPM_CONDITION_FLAGS { get; } = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");

    public const uint cFWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    public static Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 { get; } = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static Guid FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 { get; } = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    public static Guid FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 { get; } = new Guid("af80470a-5596-4c13-9992-539e6fe57967");
    public static Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 { get; } = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static Guid cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 { get; } = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    public static Guid cFWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE { get; } = new Guid("94c44912-9d6f-4ebf-b995-05ab8a088d1b");
    public static Guid cFWPM_LAYER_INBOUND_MAC_FRAME_NATIVE { get; } = new Guid("d4220bd3-62ce-4f08-ae88-b56e8526df50");
    public static Guid cFWPM_LAYER_ALE_BIND_REDIRECT_V4 { get; } = new Guid("66978cad-c704-42ac-86ac-7c1a231bd253");
    public static Guid cFWPM_SUBLAYER_UNIVERSAL { get; } = new Guid("eebecc03-ced4-4380-819a-2734397b2b74");

    public const uint cFWPM_CALLOUT_FLAG_PERSISTENT = 0x00010000;
    public const uint cFWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT = 0x00020000;
    public const uint cFWPM_CALLOUT_FLAG_REGISTERED = 0x00040000;

    public const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;
    public const uint INFINITE = 0xffffffff;
    public const uint FWPM_GENERAL_CONTEXT = 8;
    public const int FWP_V6_ADDR_SIZE = 16;
    public const int FWP_OPTION_VALUE_ALLOW_MULTICAST_STATE = 0;
    public const int FWP_OPTION_VALUE_DENY_MULTICAST_STATE = 1;
    public const int FWP_OPTION_VALUE_ALLOW_GLOBAL_MULTICAST_STATE = 2;
    public const int FWP_OPTION_VALUE_DISABLE_LOOSE_SOURCE = 0;
    public const int FWP_OPTION_VALUE_ENABLE_LOOSE_SOURCE = 1;
    public const int FWP_ACTION_FLAG_TERMINATING = 4096;
    public const int FWP_ACTION_FLAG_NON_TERMINATING = 8192;
    public const int FWP_ACTION_FLAG_CALLOUT = 16384;
    public const int FWPM_FILTER_FLAG_NONE = 0;
    public const int FWPM_FILTER_FLAG_PERSISTENT = 1;
    public const int FWPM_FILTER_FLAG_BOOTTIME = 2;
    public const int FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT = 4;
    public const int FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 8;
    public const int FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED = 16;
    public const int FWPM_FILTER_FLAG_DISABLED = 32;
    public const int FWPM_FILTER_FLAG_INDEXED = 64;
    public const int FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT = 128;
    public const int FWPM_FILTER_FLAG_SYSTEMOS_ONLY = 256;
    public const int FWPM_FILTER_FLAG_GAMEOS_ONLY = 512;
    public const uint RPC_C_AUTHN_WINNT = 10;
    public const uint RPC_C_AUTHN_DEFAULT = 0xffffffff;
}

public enum FWP_ACTION_TYPE
{
    FWP_ACTION_BLOCK = 1 | 4096,
    FWP_ACTION_PERMIT = 2 | 4096,
    FWP_ACTION_CALLOUT_TERMINATING = 3 | 16384 | 4096,
    FWP_ACTION_CALLOUT_INSPECTION = 4 | 16384 | 4096,
    FWP_ACTION_CALLOUT_UNKNOWN = 5 | 16384,
}

public enum WtIPProto
{
    cIPPROTO_ICMP = 1,
    cIPPROTO_ICMPV6 = 58,
    cIPPROTO_IPinIP = 4,
    cIPPROTO_TCP = 6,
    cIPPROTO_UDP = 17,
    cIPPROTO_ESP = 50,
    cIPPROTO_AH = 51,
};
