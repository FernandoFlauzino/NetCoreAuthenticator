using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NetCoreAuthenticator.Application.Interface;
using System.Threading;
using System.Threading.Tasks;

namespace NetCoreAuthenticator.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TwoFactorAuthenticatorsController : ControllerBase
    {
        private readonly ILogger<TwoFactorAuthenticatorsController> _logger;

        public TwoFactorAuthenticatorsController(ILogger<TwoFactorAuthenticatorsController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Gerar google authenticator
        /// </summary>
        /// <param name="service"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [HttpGet("generate")]
        public async Task<IActionResult> Generate(
            [FromServices] ITwoFactorSetupService service,
            CancellationToken cancellationToken = default)
        {

            var result = await service.GenerateTwoFactor();

            return Ok(result);
        }

        /// <summary>
        /// Validar codigo google authenticator
        /// </summary>
        /// <param name="service"></param>
        /// <param name="code"></param>
        /// <param name="userHashId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [HttpGet("validate")]
        public async Task<IActionResult> Validate(
            [FromServices] ITwoFactorSetupService service,
            string code, string privateKey,
            CancellationToken cancellationToken = default)
        {
            var result = await service.ValidateTwoFactor(privateKey, code);

            return Ok(result);
        }


        /// <summary>
        /// Gerar o codigo google authenticator
        /// </summary>
        /// <param name="service"></param>
        /// <param name="secretKey"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [HttpGet("current-pin")]
        public async Task<IActionResult> GetCurrentPin([FromServices] ITwoFactorSetupService service,
            string secretKey,
            CancellationToken cancellationToken = default)
        {
            var result = await service.GetCurrentPin(secretKey);

            return Ok(result);
        }
    }
}