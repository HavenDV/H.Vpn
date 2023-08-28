using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Windows.Win32.Networking.WinSock;
using Windows.Win32.Security;
using H.Wfp.Extensions;
using H.Wfp.Interop;

namespace H.Wfp;

[SupportedOSPlatform("windows6.0.6000")]
public static class WfpMethods
{
    public static unsafe SafeHandle CreateWfpSession(
        string name,
        string description)
    {
        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        {
            var session = new FWPM_SESSION0
            {
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                flags = PInvoke.FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec = PInvoke.INFINITE,
            };

            HANDLE handle;
            PInvoke.FwpmEngineOpen0(
                serverName: default,
                authnService: PInvoke.RPC_C_AUTHN_WINNT,
                authIdentity: null,
                session: &session,
                engineHandle: &handle).EnsureResultIsNull();

            return new SafeWfpSessionHandle(handle, ownsHandle: true);
        }
    }

    public static void BeginTransaction(this SafeHandle handle)
    {
        PInvoke.FwpmTransactionBegin0(
            engineHandle: handle,
            flags: 0).EnsureResultIsNull();
    }

    public static void CommitTransaction(this SafeHandle handle)
    {
        PInvoke.FwpmTransactionCommit0(
            engineHandle: handle).EnsureResultIsNull();
    }

    public static void AbortTransaction(this SafeHandle handle)
    {
        PInvoke.FwpmTransactionAbort0(
            engineHandle: handle).EnsureResultIsNull();
    }

    public static unsafe Guid AddProviderContext(
        this SafeHandle handle,
        Guid providerKey,
        string name,
        string description,
        IPAddress ipAddress)
    {
        var id = 0UL;
        var guid = Guid.NewGuid();

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        fixed (byte* addressPtr = ipAddress.GetAddressBytes())
        {
            var blob = new FWP_BYTE_BLOB
            {
                data = addressPtr,
                size = 4,
            };
            var context = new FWPM_PROVIDER_CONTEXT0
            {
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                type = FWPM_PROVIDER_CONTEXT_TYPE.FWPM_GENERAL_CONTEXT,
                providerContextKey = guid,
                Anonymous = new FWPM_PROVIDER_CONTEXT0._Anonymous_e__Union
                {
                    dataBuffer = &blob,
                },
                providerKey = &providerKey,
            };
            PInvoke.FwpmProviderContextAdd0(
                engineHandle: handle,
                providerContext: in context,
                sd: new PSECURITY_DESCRIPTOR(),
                id: &id).EnsureResultIsNull();
        }

        return guid;
    }

    public static unsafe Guid AddProvider(
        this SafeHandle handle,
        string name,
        string description)
    {
        var guid = Guid.NewGuid();

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        {
            var provider = new FWPM_PROVIDER0
            {
                providerKey = guid,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
            };
            PInvoke.FwpmProviderAdd0(
                engineHandle: handle,
                provider: in provider,
                sd: new PSECURITY_DESCRIPTOR()).EnsureResultIsNull();
        }

        return guid;
    }

    public static unsafe Guid AddSubLayer(
        this SafeHandle handle,
        Guid providerKey,
        string name,
        string description)
    {
        var guid = Guid.NewGuid();

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        {
            var subLayer = new FWPM_SUBLAYER0
            {
                subLayerKey = guid,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                providerKey = &providerKey,
                flags = 0,
                weight = 0,
            };
            PInvoke.FwpmSubLayerAdd0(
                engineHandle: handle,
                subLayer: in subLayer,
                sd: new PSECURITY_DESCRIPTOR()).EnsureResultIsNull();
        }

        return guid;
    }

    public static unsafe SafeFwpmHandle GetAppIdFromFileName(string fileName)
    {
        var blobPtr = (FWP_BYTE_BLOB*)null;
        fixed (char* fileNamePtr = fileName)
        {
            PInvoke.FwpmGetAppIdFromFileName0(
                fileName: fileNamePtr,
                appId: &blobPtr).EnsureResultIsNull();
        }
        
        return new SafeFwpmHandle((IntPtr)blobPtr, true);
    }

    public static unsafe Guid AddCallout(
        this SafeHandle handle,
        Guid calloutKey,
        Guid providerKey,
        Guid applicableLayer,
        string name,
        string description)
    {
        var id = 0U;

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        {
            var callout = new FWPM_CALLOUT0
            {
                calloutKey = calloutKey,
                providerKey = &providerKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                applicableLayer = applicableLayer,
                flags = PInvoke.FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT,
            };
            PInvoke.FwpmCalloutAdd0(
                engineHandle: handle,
                callout: in callout,
                sd: new PSECURITY_DESCRIPTOR(),
                id: &id).EnsureResultIsNull();
        }

        return calloutKey;
    }

    public static unsafe Guid AllowSplitAppIds(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        SafeFwpmHandle[] appIds,
        byte weight,
        Guid providerContextKey,
        Guid actionFilterGuid,
        bool reversed,
        string name,
        string description)
    {
        var conditions = appIds
            .Select(appId => new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_ALE_APP_ID,
                matchType = reversed
                    ? FWP_MATCH_TYPE.FWP_MATCH_NOT_EQUAL
                    : FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        byteBlob = (FWP_BYTE_BLOB*)appId.DangerousGetHandle(),
                    }
                }
            })
            .ToArray();
        var id = 0UL;
        var guid = Guid.NewGuid();

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        fixed (FWPM_FILTER_CONDITION0* conditionsPtr = conditions)
        {
            var filter = new FWPM_FILTER0
            {
                filterKey = guid,
                providerKey = &providerKey,
                subLayerKey = subLayerKey,
                weight = new FWP_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    Anonymous = new FWP_VALUE0._Anonymous_e__Union
                    {
                        uint8 = weight,
                    }
                },
                numFilterConditions = (uint)appIds.Length,
                filterCondition = conditionsPtr,
                flags = FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT,
                action = new FWPM_ACTION0
                {
                    type = (uint)FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_UNKNOWN,
                    Anonymous = new FWPM_ACTION0._Anonymous_e__Union
                    {
                        filterType = actionFilterGuid,
                    }
                },
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                Anonymous = new FWPM_FILTER0._Anonymous_e__Union
                {
                    providerContextKey = providerContextKey,
                },
                layerKey = layerKey,
            };
            PInvoke.FwpmFilterAdd0(
                engineHandle: handle,
                filter: in filter,
                sd: new PSECURITY_DESCRIPTOR(),
                id: &id).EnsureResultIsNull();
        }

        return guid;
    }

    public static unsafe Guid PermitAppId(
        this SafeHandle handle,
        Guid providerKey, 
        Guid subLayerKey, 
        Guid layerKey,
        SafeFwpmHandle appId, 
        byte weight, 
        string name, 
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_ALE_APP_ID,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        byteBlob = (FWP_BYTE_BLOB*)appId.DangerousGetHandle(),
                    }
                }
            });
    }

    public static unsafe Guid AddPeerName(
        this SafeHandle handle,
        FWP_ACTION_TYPE action,
        Guid providerKey, 
        Guid subLayerKey, 
        Guid layerKey,
        Uri uri,
        byte weight, 
        string name, 
        string description)
    {
        var bytes = Encoding.UTF8.GetBytes(uri.Host);
        
        fixed (byte* bytesPtr = bytes)
        {
            var blob = new FWP_BYTE_BLOB
            {
                data = bytesPtr,
                size = (uint)bytes.Length,
            };
            
            return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
                action, new FWPM_FILTER_CONDITION0
                {
                    fieldKey = PInvoke.FWPM_CONDITION_PEER_NAME,
                    matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                        Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                        {
                            byteBlob = &blob,
                        }
                    }
                });
        }
    }

    public static Guid PermitLoopback(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_FLAGS,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_FLAGS_ALL_SET,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT32,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint32 = PInvoke.FWP_CONDITION_FLAG_IS_LOOPBACK,
                    }
                }
            });
    }

    public static Guid BlockAll(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_BLOCK);
    }

    internal static FWPM_FILTER_CONDITION0[] DnsConditions { get; } = {
        new FWPM_FILTER_CONDITION0
        {
            fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_PORT,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT16,
                Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                {
                    uint16 = 53, // DNS PORT
                }
            }
        },
        new FWPM_FILTER_CONDITION0
        {
            fieldKey = PInvoke.FWPM_CONDITION_IP_PROTOCOL,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT8,
                Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                {
                    uint8 = (byte)IPPROTO.IPPROTO_UDP,
                }
            }
        },
        new FWPM_FILTER_CONDITION0
        {
            fieldKey = PInvoke.FWPM_CONDITION_IP_PROTOCOL,
            matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
            conditionValue = new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT8,
                Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                {
                    uint8 = (byte)IPPROTO.IPPROTO_TCP,
                }
            }
        },
    };

    public static Guid BlockDns(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_BLOCK, DnsConditions);
    }

    public static Guid AddDnsV4(
        this SafeHandle handle,
        FWP_ACTION_TYPE action,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        IEnumerable<IPAddress> addresses,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            action,
            DnsConditions
                .Concat(addresses.Select(address => new FWPM_FILTER_CONDITION0
                {
                    fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_DATA_TYPE.FWP_UINT32,
                        Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                        {
                            uint32 = address.ToInteger(),
                        }
                    }
                }))
                .ToArray());
    }

    public static Guid AddAddressV4(
        this SafeHandle handle,
        FWP_ACTION_TYPE action,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        IEnumerable<IPAddress> addresses,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            action,
            addresses.Select(address => new FWPM_FILTER_CONDITION0
                {
                    fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_DATA_TYPE.FWP_UINT32,
                        Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                        {
                            uint32 = address.ToInteger(),
                        }
                    }
                })
                .ToArray());
    }

    // public static unsafe Guid AllowDnsV6(
    //     this SafeHandle handle,
    //     Guid providerKey,
    //     Guid subLayerKey,
    //     Guid layerKey,
    //     byte weight,
    //     IEnumerable<IPAddress> addresses,
    //     string name,
    //     string description)
    // {
    //     var ptrs = addresses
    //         .Select(address => address.ToArray16())
    //         .ToArray();
    //
    //     return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
    //         FWP_ACTION_TYPE.FWP_ACTION_PERMIT,
    //         DnsConditions
    //             .Concat(ptrs.Select(ptr => new FWPM_FILTER_CONDITION0
    //             {
    //                 fieldKey = NativeConstants.cFWPM_CONDITION_IP_REMOTE_ADDRESS,
    //                 matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
    //                 conditionValue = new FWP_CONDITION_VALUE0
    //                 {
    //                     type = FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE,
    //                     Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
    //                     {
    //                         byteArray16 = &ptr,
    //                     }
    //                 }
    //             }))
    //             .ToArray());
    // }

    public static unsafe Guid PermitNetworkInterface(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        ulong ifLuid,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT64,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint64 = &ifLuid,
                    }
                }
            });
    }

    public static unsafe Guid PermitSubNetworkV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        IPAddress address,
        IPAddress mask,
        bool isLocalAddress,
        string name,
        string description)
    {
        var network = new FWP_V4_ADDR_AND_MASK
        {
            addr = address.ToInteger(),
            mask = mask.ToInteger(),
        };

        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = isLocalAddress
                    ? PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS
                    : PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_V4_ADDR_MASK,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        v4AddrMask = &network,
                    }
                }
            });
    }

    public static Guid PermitTcpPortV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        ushort port,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_PROTOCOL,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint8 = (byte)IPPROTO.IPPROTO_TCP,
                    }
                }
            }, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_PORT,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT16,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint16 = port,
                    }
                }
            });
    }

    public static Guid PermitUdpPortV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        ushort port,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description,
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_PROTOCOL,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint8 = (byte)IPPROTO.IPPROTO_UDP,
                    }
                }
            }, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_REMOTE_PORT,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT16,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint16 = port,
                    }
                }
            });
    }

    public static Guid PermitProtocolV4(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        byte proto,
        string name,
        string description)
    {
        return AddFilter(handle, providerKey, subLayerKey, layerKey, weight, name, description, 
            FWP_ACTION_TYPE.FWP_ACTION_PERMIT, new FWPM_FILTER_CONDITION0
            {
                fieldKey = PInvoke.FWPM_CONDITION_IP_PROTOCOL,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    Anonymous = new FWP_CONDITION_VALUE0._Anonymous_e__Union
                    {
                        uint8 = proto,
                    }
                }
            });
    }

    internal static unsafe Guid AddFilter(
        this SafeHandle handle,
        Guid providerKey,
        Guid subLayerKey,
        Guid layerKey,
        byte weight,
        string name,
        string description,
        FWP_ACTION_TYPE actionType,
        params FWPM_FILTER_CONDITION0[] conditions)
    {
        var id = 0UL;
        var guid = Guid.NewGuid();

        fixed (char* namePtr = name)
        fixed (char* descriptionPtr = description)
        fixed (FWPM_FILTER_CONDITION0* conditionsPtr = conditions)
        {
            var filter = new FWPM_FILTER0
            {
                filterKey = guid,
                providerKey = &providerKey,
                subLayerKey = subLayerKey,
                weight = new FWP_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    Anonymous = new FWP_VALUE0._Anonymous_e__Union
                    {
                        uint8 = weight,
                    }
                },
                numFilterConditions = (uint)conditions.Length,
                filterCondition = conditionsPtr,
                action = new FWPM_ACTION0
                {
                    type = (uint)actionType,
                },
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = namePtr,
                    description = descriptionPtr,
                },
                layerKey = layerKey,
            };
            PInvoke.FwpmFilterAdd0(
                engineHandle: handle,
                filter: in filter,
                sd: new PSECURITY_DESCRIPTOR(),
                id: &id).EnsureResultIsNull();
        }

        return guid;
    }

    public static void EnsureResultIsNull(this uint result)
    {
        Marshal.ThrowExceptionForHR((int)result);
    }
}
