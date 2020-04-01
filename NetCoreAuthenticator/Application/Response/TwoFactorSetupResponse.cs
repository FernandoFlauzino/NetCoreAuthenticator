namespace NetCoreAuthenticator.Application.Response
{
    public class TwoFactorSetupResponse
    {
        public string Account { get; set; }
        public string AccountSecretKey { get; set; }
        public string ManualEntryKey { get; set; }
        public string QrCodeSetupImageUrl { get; set; }
    }
}
