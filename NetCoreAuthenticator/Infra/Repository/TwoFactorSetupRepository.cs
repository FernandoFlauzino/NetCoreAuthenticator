using NetCoreAuthenticator.Application.Interface.Api;
using NetCoreAuthenticator.Application.Response;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetCoreAuthenticator.Infra.Repository
{
    public class TwoFactorSetupRepository : ITwoFactorSetupRepository
    {

        private readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private TimeSpan DefaultClockDriftTolerance { get; }
        private bool UseManagedSha1Algorithm { get; }
        private bool TryUnmanagedAlgorithmOnFailure { get; }

        public TwoFactorSetupRepository() : this(true, true)
        {
        }

        private TwoFactorSetupRepository(bool useManagedSha1, bool useUnmanagedOnFail)
        {
            DefaultClockDriftTolerance = TimeSpan.FromMinutes(5);
            UseManagedSha1Algorithm = useManagedSha1;
            TryUnmanagedAlgorithmOnFailure = useUnmanagedOnFail;
        }

        public async Task<string> GetCurrentPin(string accountSecretKey)
        {
            var result = GeneratePinAtInterval(accountSecretKey, GetCurrentCounter());

            return await Task.FromResult(result);
        }

        public TwoFactorSetupResponse Generate(string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return Generate(null, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight);
        }

        public TwoFactorSetupResponse Generate(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight)
        {
            return GenerateSetupCode(issuer, accountTitleNoSpaces, accountSecretKey, qrCodeWidth, qrCodeHeight, false);
        }
        public string[] GetCurrentPins(string accountSecretKey)
        {
            return GetCurrentPins(accountSecretKey, DefaultClockDriftTolerance);
        }

        public bool ValidateTwoFactorPin(string accountSecretKey, string twoFactorCodeFromClient)
        {
            return ValidateTwoFactorPin(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        private bool ValidateTwoFactorPin(string accountSecretKey, string twoFactorCodeFromClient, TimeSpan timeTolerance)
        {
            var codes = GetCurrentPins(accountSecretKey, timeTolerance);
            return codes.Any(c => c == twoFactorCodeFromClient);
        }

        private TwoFactorSetupResponse GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, int qrCodeWidth, int qrCodeHeight, bool useHttps)
        {
            if (accountTitleNoSpaces == null) { throw new NullReferenceException("Account Title is null"); }

            accountTitleNoSpaces = accountTitleNoSpaces.Replace(" ", "");

            var twoFactorSetup = new TwoFactorSetupResponse
            {
                Account = accountTitleNoSpaces,
                AccountSecretKey = accountSecretKey

            };

            var encodedSecretKey = EncodeAccountSecretKey(accountSecretKey);
            twoFactorSetup.ManualEntryKey = encodedSecretKey;

            string provisionUrl;

            if (string.IsNullOrEmpty(issuer))
            {
                provisionUrl = UrlEncode(String.Format("otpauth://totp/{0}?secret={1}", accountTitleNoSpaces, encodedSecretKey));
            }
            else
            {
                provisionUrl = UrlEncode(String.Format("otpauth://totp/{0}?secret={1}&issuer={2}", accountTitleNoSpaces, encodedSecretKey, UrlEncode(issuer)));
            }

            var protocol = useHttps ? "https" : "http";
            var url =
                $"{protocol}://chart.googleapis.com/chart?cht=qr&chs={qrCodeWidth}x{qrCodeHeight}&chl={provisionUrl}";

            twoFactorSetup.QrCodeSetupImageUrl = url;

            return twoFactorSetup;
        }

        private static string UrlEncode(string value)
        {
            var result = new StringBuilder();
            var validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (char symbol in value)
            {
                if (validChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + string.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString().Replace(" ", "%20");
        }

        private string EncodeAccountSecretKey(string accountSecretKey)
        {

            return Base32Encode(Encoding.UTF8.GetBytes(accountSecretKey));
        }

        private static string Base32Encode(byte[] data)
        {
            const int inByteSize = 8;
            const int outByteSize = 5;
            var i = 0;
            var index = 0;
            var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();


            var result = new StringBuilder((data.Length + 7) * inByteSize / outByteSize);

            while (i < data.Length)
            {
                int digit;

                var currentByte = (data[i] >= 0) ? data[i] : (data[i] + 256);

                if (index > (inByteSize - outByteSize))
                {
                    int nextByte;
                    if ((i + 1) < data.Length)
                        nextByte = (data[i + 1] >= 0) ? data[i + 1] : (data[i + 1] + 256);
                    else
                        nextByte = 0;

                    digit = currentByte & (0xFF >> index);
                    index = (index + outByteSize) % inByteSize;
                    digit <<= index;
                    digit |= nextByte >> (inByteSize - index);
                    i++;
                }
                else
                {
                    digit = (currentByte >> (inByteSize - (index + outByteSize))) & 0x1F;
                    index = (index + outByteSize) % inByteSize;
                    if (index == 0)
                        i++;
                }
                result.Append(alphabet[digit]);
            }

            return result.ToString();
        }

        public string GeneratePinAtInterval(string accountSecretKey, long counter, int digits = 6)
        {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        private string GenerateHashedCode(string secret, long iterationNumber, int digits = 6)
        {
            byte[] key = Encoding.UTF8.GetBytes(secret);
            return GenerateHashedCode(key, iterationNumber, digits);
        }

        private string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6)
        {
            var counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            var hmac = GetHmacSha1Algorithm(key);

            var hash = hmac.ComputeHash(counter);

            var offset = hash[hash.Length - 1] & 0xf;

            var binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | (hash[offset + 3]);

            var password = binary % (int)Math.Pow(10, digits);
            return password.ToString(new string('0', digits));
        }

        public long GetCurrentCounter()
        {
            return GetCurrentCounter(DateTime.UtcNow, _epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep)
        {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }

        /// <summary>
        /// Creates a HMACSHA1 algorithm to use to hash the counter bytes. By default, this will attempt to use
        /// the managed SHA1 class (SHA1Manager) and on exception (FIPS-compliant machine policy, etc) will attempt
        /// to use the unmanaged SHA1 class (SHA1CryptoServiceProvider).
        /// </summary>
        /// <param name="key">User's secret key, in bytes</param>
        /// <returns>HMACSHA1 cryptographic algorithm</returns>        
        private HMACSHA1 GetHmacSha1Algorithm(byte[] key)
        {
            HMACSHA1 hmac;

            try
            {
                hmac = new HMACSHA1(key, UseManagedSha1Algorithm);
            }
            catch (InvalidOperationException ioe)
            {
                if (UseManagedSha1Algorithm && TryUnmanagedAlgorithmOnFailure)
                {
                    try
                    {
                        hmac = new HMACSHA1(key, false);
                    }
                    catch (InvalidOperationException ioe2)
                    {
                        throw ioe2;
                    }
                }
                else
                {
                    throw ioe;
                }
            }

            return hmac;
        }

        private string[] GetCurrentPins(string accountSecretKey, TimeSpan timeTolerance)
        {
            var codes = new List<string>();
            var iterationCounter = GetCurrentCounter();
            var iterationOffset = 0;

            if (timeTolerance.TotalSeconds > 30)
            {
                iterationOffset = Convert.ToInt32(timeTolerance.TotalSeconds / 30.00);
            }

            var iterationStart = iterationCounter - iterationOffset;
            var iterationEnd = iterationCounter + iterationOffset;

            for (var counter = iterationStart; counter <= iterationEnd; counter++)
            {
                codes.Add(GeneratePinAtInterval(accountSecretKey, counter));
            }

            return codes.ToArray();
        }
    }
}
