using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using NetCoreAuthenticator.Application.Interface;
using NetCoreAuthenticator.Application.Interface.Api;
using NetCoreAuthenticator.Infra.Repository;
using NetCoreAuthenticator.Service;
using System;
using System.IO;
using System.Reflection;

namespace NetCoreAuthenticator.Infra.IoC
{
    public class DependencyInjector
    {

        private static IServiceProvider _serviceProvider;
        private static IServiceCollection _services;
        public static T GetService<T>()
        {
            _services = _services ?? RegisterServices();
            _serviceProvider = _serviceProvider ?? _services.BuildServiceProvider();
            return _serviceProvider.GetService<T>();
        }

        public static IServiceCollection RegisterServices()
        {
            IConfigurationBuilder builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json");
            IConfiguration configuration = builder.Build();

            return RegisterServices(new ServiceCollection(), configuration);
        }

        public static IServiceCollection RegisterServices(IServiceCollection services, IConfiguration configuration)
        {
            _services = services;

            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1",
                    new OpenApiInfo
                    {
                        Title = "PdaSecurityService",
                        Version = Assembly.GetExecutingAssembly().GetName().Version.ToString(),
                        Description = "Documentação da API de autenticação dos Assessores de Investimentos. \r\n"

                    }
                );
            });


            services.AddControllers();

            services.AddScoped<ITwoFactorSetupService, TwoFactorSetupService>();

            services.AddScoped<ITwoFactorSetupRepository, TwoFactorSetupRepository>();

            services.AddMvc();

            services.AddControllersWithViews();

            return _services;
        }
    }
}
