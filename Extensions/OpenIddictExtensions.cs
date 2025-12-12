using SmartSkor.Identity.Server.Data;

namespace SmartSkor.Identity.Server.Extensions;

public static class OpenIddictExtensions
{
    public static IServiceCollection AddOpenIddictServer(this IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<SmartSkorIdentityDbContext>();
            })
            .AddServer(options =>
            {
                // Enable endpoints
                options.SetAuthorizationEndpointUris("/connect/authorize")
                    .SetTokenEndpointUris("/connect/token")
                    .SetUserInfoEndpointUris("/connect/userinfo")
                    .SetEndSessionEndpointUris("/connect/logout");

                // Enable authorization code flow with PKCE
                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange();

                // Enable refresh tokens
                options.AllowRefreshTokenFlow();

                // Register scopes
                options.RegisterScopes("openid", "profile", "email", "offline_access", "api");

                // Development certificates (replace in production)
                options.AddDevelopmentEncryptionCertificate()
                    .AddDevelopmentSigningCertificate();

                // Use JWT access tokens
                options.DisableAccessTokenEncryption();

                // Register ASP.NET Core host
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}