
namespace NetCoreAuthenticator.Application.Response
{
    public class TwoFactorValidateResponse
    {
        public bool IsValid { get; set; }
        public int Attempts { get; set; }

        public bool IsBlocked { get; set; }
    }
}
