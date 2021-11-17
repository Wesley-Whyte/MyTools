using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Diagnostics;
using Serilog;
using Newtonsoft.Json;
using AspNetCoreRateLimit;

namespace 
    Tools.Net5ApiConfigurations
{
    public static class ServiceExtensions
    {
        /// <summary>
        /// Adds and configures identity system for specified User types
        /// </summary>
        /// <typeparam name="TUser">Specified user type</typeparam>
        /// <param name="services"></param>
        /// <param name="setupAction">An action to configure identity options</param>
        public static void ConfigureIdentity<TUser>(this IServiceCollection services, Action<IdentityOptions> setupAction)  where TUser : class
        {
            var builder = services.AddIdentityCore<TUser>(setupAction);
        }

        /// <summary>
        /// Adds my default identity system configuration for the specified User types
        /// </summary>
        /// <typeparam name="TUser"></typeparam>
        /// <param name="services"></param>
        public static void ConfigureIdentity<TUser>(this IServiceCollection services) where TUser : class
        {
            services.AddIdentityCore<TUser>(x =>
            {
                x.User.RequireUniqueEmail = true;
                x.Password.RequireDigit = true;
                x.Password.RequiredLength = 8;
            });
        }

        /// <summary>
        /// Adds my default identity system configuration for the specified User and Role types
        /// </summary>
        /// <typeparam name="TUser"></typeparam>
        /// <typeparam name="TRoles"></typeparam>
        /// <param name="services"></param>
        public static void ConfigureIdentity<TUser, TRoles>(this IServiceCollection services)
        where TUser : class
        where TRoles : class
        {
            var builder = services.AddIdentityCore<TUser>(x =>
            {
                x.User.RequireUniqueEmail = true;
                x.Password.RequireDigit = true;
                x.Password.RequiredLength = 8;
            });
            builder.AddRoles<TRoles>();
        }

        /// <summary>
        /// Adds and configures identity system for specified User and Role types
        /// </summary>
        /// <typeparam name="TUser"></typeparam>
        /// <typeparam name="TRoles"></typeparam>
        /// <param name="services"></param>
        /// <param name="setupAction">An action to configure identity options</param>
        public static void ConfigureIdentity<TUser, TRoles>(this IServiceCollection services, Action<IdentityOptions> setupAction) 
        where TUser : class 
        where TRoles : class
        {
            var builder = services.AddIdentityCore<TUser>(setupAction);
            builder.AddRoles<TRoles>();
        }

        /// <summary>
        /// Registers and configures services required by an authentication service using Jwt
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <param name="configureOptions">A delegate to configure authentication services</param>
        /// <param name="JwtOptions">A delegate to allow configuring JwtBearer options</param>
        public static void ConfigureJWT(this IServiceCollection services, IConfiguration configuration,
            Action<AuthenticationOptions> configureOptions, Action<JwtBearerOptions> JwtOptions)
        {
            var jwtSettings = configuration.GetSection("Jwt");
            var key = Environment.GetEnvironmentVariable("KEY");

            services.AddAuthentication(configureOptions).AddJwtBearer(JwtOptions);
        }

        /// <summary>
        /// Registers my default configuration services required by an authentication service using Jwt
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        public static void ConfigureJWT(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("Jwt");
            var key = Environment.GetEnvironmentVariable("KEY");

            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.GetSection("Issuer").Value,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                };
            });
        }

        /// <summary>
        /// Configures Exception handling middleware
        /// </summary>
        /// <param name="app"></param>
        public static void CongigureExceptionHandler(this IApplicationBuilder app)
        {
            app.UseExceptionHandler(error =>
            {
                error.Run(async context =>
                {
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    context.Response.ContentType = "application.json";
                    var contextFeature = context.Features.Get<IExceptionHandlerFeature>();

                    if (contextFeature != null)
                    {
                        Log.Error($"Something went wrong int the {contextFeature.Error}");

                        await context.Response.WriteAsync(new Error
                        {
                            StatusCode = context.Response.StatusCode,
                            Message = "Internal Server error. Please try again"
                        }.ToString());
                    }
                });
            });
        }

        /// <summary>
        /// Configures API Versioning services
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureVersioning(IServiceCollection services)
        {
            services.AddApiVersioning(x =>
            {
                x.ReportApiVersions = true;
                x.AssumeDefaultVersionWhenUnspecified = true;
                x.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);
            });
        }

        /// <summary>
        /// Configures API Rate limiting services with my default rules
        /// Requires IpRateLimitng middleware
        /// </summary>
        /// <param name="services"></param>
        public static void ConfigureRateLimiiting(this IServiceCollection services)
        {
            var rateLimitRules = new List<RateLimitRule>
            {
                new RateLimitRule
                {
                    Endpoint = "*",
                    Limit = 1,
                    Period = "5s"
                }
            };

            services.Configure<IpRateLimitOptions>(o =>
            {
                o.GeneralRules = rateLimitRules;
            });

            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

        }

        /// <summary>
        /// Configures API Rate limiting services
        /// Requires IpRateLimitng middleware
        /// </summary>
        /// <param name="services"></param>
        /// <param name="rateLimitRules">Rules for rate limiting</param>
        public static void ConfigureRateLimiiting(this IServiceCollection services, List<RateLimitRule> rateLimitRules)
        {
            services.Configure<IpRateLimitOptions>(o =>
            {
                o.GeneralRules = rateLimitRules;
            });

            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
        }


    }

    public class Error
    {
        public int StatusCode { get; set; }

        public string Message { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this);
        }
    }
}
