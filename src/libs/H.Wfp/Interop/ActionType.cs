namespace H.Wfp.Interop;

public enum ActionType
{
    None,
    NoneNoMatch,
    Block,
    Permit,
    CalloutTerminating,
    CalloutInspection,
    CalloutUnknown,
}

internal static class ActionTypeExtensions
{
    public static FWP_ACTION_TYPE ToFwpActionType(this ActionType actionType)
    {
        return actionType switch
        {
            ActionType.None => FWP_ACTION_TYPE.FWP_ACTION_NONE,
            ActionType.NoneNoMatch => FWP_ACTION_TYPE.FWP_ACTION_NONE_NO_MATCH,
            ActionType.Block => FWP_ACTION_TYPE.FWP_ACTION_BLOCK,
            ActionType.Permit => FWP_ACTION_TYPE.FWP_ACTION_PERMIT,
            ActionType.CalloutTerminating => FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_TERMINATING,
            ActionType.CalloutInspection => FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_INSPECTION,
            ActionType.CalloutUnknown => FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_UNKNOWN,
            _ => throw new NotImplementedException(),
        };
    }
}
