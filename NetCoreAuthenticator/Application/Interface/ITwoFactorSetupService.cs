using NetCoreAuthenticator.Application.Response;
using System.Threading.Tasks;

namespace NetCoreAuthenticator.Application.Interface
{
    public interface ITwoFactorSetupService
    {
        Task<TwoFactorResponse> GenerateTwoFactor();

        Task<TwoFactorValidateResponse> ValidateTwoFactor(string accountSecretKey,string twoFactorCodeFromClient);

        Task<string> GetCurrentPin(string accountSecretKey);
    }
}
