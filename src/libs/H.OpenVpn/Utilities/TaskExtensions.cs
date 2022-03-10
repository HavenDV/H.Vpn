namespace H.OpenVpn.Utilities;

public static class TaskExtensions
{
    public static Task WithCancellation(this Task task, CancellationToken cancellationToken)
    {
        task = task ?? throw new ArgumentNullException(nameof(task));

        return task.IsCompleted
            ? task
            : task.ContinueWith(
                completedTask => completedTask.GetAwaiter().GetResult(),
                cancellationToken,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
    }

    public static Task<T> WithCancellation<T>(this Task<T> task, CancellationToken cancellationToken)
    {
        task = task ?? throw new ArgumentNullException(nameof(task));

        return task.IsCompleted
            ? task
            : task.ContinueWith(
                completedTask => completedTask.GetAwaiter().GetResult(),
                cancellationToken,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
    }
}
