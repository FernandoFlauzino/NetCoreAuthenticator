using NetCoreAuthenticator.Application.Response;

namespace NetCoreAuthenticator.Application.Interface.Api
{
    public interface ITwoFactorSetupRepository
    {
        TwoFactorSetupResponse Generate(string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth,
            int qrCodeHeight);

        TwoFactorSetupResponse Generate(string issuer, string accountTitleNoSpaces, string accountSecretKey,
            int qrCodeWidth, int qrCodeHeight);

        string[] GetCurrentPins(string accountSecretKey);

        bool ValidateTwoFactorPin(string accountSecretKey, string twoFactorCodeFromClient);

        string GeneratePinAtInterval(string accountSecretKey, long counter, int digits = 6);

        long GetCurrentCounter();
    }
}
