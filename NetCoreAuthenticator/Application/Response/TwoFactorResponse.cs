
namespace NetCoreAuthenticator.Application.Response
{
    public class TwoFactorResponse
    {
        public string AccountSecretKey { get; set; }

        public string ManualEntryKey { get; set; }
    }
}
