using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SmartSkor.Identity.Server.Data;

public class SeedData
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        var manager = services.GetRequiredService<IOpenIddictApplicationManager>();

        // Register the Next.js client (smartskor-web)
        if (await manager.FindByClientIdAsync("smartskor-web") is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "smartskor-web",
                ClientSecret = "smartskor-web-secret-change-in-production",
                DisplayName = "SmartSkor Web Application",
                ConsentType = ConsentTypes.Implicit,
                RedirectUris =
                {
                    new Uri("http://localhost:3000/api/auth/callback/openiddict")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:3000"),
                    new Uri("http://localhost:3000/signed-out")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Introspection,

                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,

                    Permissions.ResponseTypes.Code,

                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "offline_access",
                    Permissions.Prefixes.Scope + "api"
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
    }
}