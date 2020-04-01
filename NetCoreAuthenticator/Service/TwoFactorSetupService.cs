using NetCoreAuthenticator.Application.Interface;
using NetCoreAuthenticator.Application.Interface.Api;
using NetCoreAuthenticator.Application.Response;
using System;
using System.Threading.Tasks;

namespace NetCoreAuthenticator.Service
{
    public class TwoFactorSetupService : ITwoFactorSetupService
    {
        private readonly ITwoFactorSetupRepository _twoFactorSetupRepository;

        public TwoFactorSetupService(ITwoFactorSetupRepository twoFactorSetupRepository)
        {
            _twoFactorSetupRepository = twoFactorSetupRepository;
        }

        public async Task<TwoFactorResponse> GenerateTwoFactor()
        {
            var secretKey = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);

            var result = _twoFactorSetupRepository.Generate("Guide", "guide@guide.com.br", secretKey, 300, 300);

            var twoFactor = CreateViewModel(result);

            return await Task.FromResult(twoFactor);
        }

        public async Task<TwoFactorValidateResponse> ValidateTwoFactor(string accountSecretKey, string twoFactorCodeFromClient)
        {

            var response = new TwoFactorValidateResponse
            {
                IsValid = _twoFactorSetupRepository.ValidateTwoFactorPin(accountSecretKey, twoFactorCodeFromClient)
            };

            return await Task.FromResult(response);
        }

        public async Task<string> GetCurrentPin(string accountSecretKey)
        {
            var result = _twoFactorSetupRepository.GeneratePinAtInterval(accountSecretKey, _twoFactorSetupRepository.GetCurrentCounter());

            return await Task.FromResult(result);
        }

        protected TwoFactorResponse CreateViewModel(TwoFactorSetupResponse entity)
        {
            return new TwoFactorResponse
            {
                AccountSecretKey = entity.AccountSecretKey,
                ManualEntryKey = entity.ManualEntryKey

            };
        }



    }
}
