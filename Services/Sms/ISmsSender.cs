namespace krabo_gold.Services.Sms;

public interface ISmsSender
{
    Task SendOtpAsync(
        string mobile,
        string code,
        CancellationToken cancellationToken = default);
}