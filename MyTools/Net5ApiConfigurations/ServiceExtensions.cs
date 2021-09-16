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

namespace MyTools.Net5ApiConfigurations
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


    }
}
