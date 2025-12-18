using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SmartSkor.Identity.Server.Data;

public class SeedData
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        var applicationManager = services.GetRequiredService<IOpenIddictApplicationManager>();
        var scopeManager = services.GetRequiredService<IOpenIddictScopeManager>();

        // ============================================
        // Register API Scopes
        // ============================================

        // Register the smartskor-api scope
        if (await scopeManager.FindByNameAsync("smartskor-api") is null)
        {
            await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "smartskor-api",
                DisplayName = "SmartSkor API",
                Description = "Access to the SmartSkor API",
                Resources =
                {
                    "smartskor-api" // This becomes the 'aud' claim in the token
                }
            });
        }

        // ============================================
        // Register Client Applications
        // ============================================

        // Register the Next.js client (smartskor-web)
        if (await applicationManager.FindByClientIdAsync("smartskor-web") is null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "smartskor-web",
                ClientSecret = "smartskor-web-secret-change-in-production",
                DisplayName = "SmartSkor Web Application",
                ConsentType = ConsentTypes.Implicit,
                RedirectUris =
                {
                    new Uri("http://localhost:3000/api/auth/callback/openiddict"),
                    new Uri("https://localhost:3000/api/auth/callback/openiddict"),
                    // Add production URLs here
                    // new Uri("https://app.smartskor.com/api/auth/callback/openiddict")
                },
                PostLogoutRedirectUris =
                {
                    new Uri("http://localhost:3000"),
                    new Uri("http://localhost:3000/signed-out"),
                    new Uri("https://localhost:3000"),
                    new Uri("https://localhost:3000/signed-out"),
                    // Add production URLs here
                    // new Uri("https://app.smartskor.com"),
                    // new Uri("https://app.smartskor.com/signed-out")
                },
                Permissions =
                {
                    // Endpoints
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Introspection,
                    Permissions.Endpoints.Revocation,
                    
                    // Grant types
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    
                    // Response types
                    Permissions.ResponseTypes.Code,
                    
                    // Standard scopes
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "offline_access",
                    
                    // API scope - this allows the web app to request API access
                    Permissions.Prefixes.Scope + "smartskor-api"
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
        else
        {
            // Update existing client to ensure it has the API scope permission
            var existingClient = await applicationManager.FindByClientIdAsync("smartskor-web");
            if (existingClient != null)
            {
                var descriptor = new OpenIddictApplicationDescriptor();
                await applicationManager.PopulateAsync(descriptor, existingClient);

                // Add smartskor-api scope if not present
                var apiScopePermission = Permissions.Prefixes.Scope + "smartskor-api";
                if (!descriptor.Permissions.Contains(apiScopePermission))
                {
                    descriptor.Permissions.Add(apiScopePermission);
                    await applicationManager.UpdateAsync(existingClient, descriptor);
                }
            }
        }

        // Register Swagger UI client (for API testing)
        if (await applicationManager.FindByClientIdAsync("swagger-ui") is null)
        {
            await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "swagger-ui",
                DisplayName = "Swagger UI",
                ConsentType = ConsentTypes.Implicit,
                ClientType = ClientTypes.Public, // Swagger UI is a public client (no secret)
                RedirectUris =
                {
                    // Local development
                    new Uri("http://localhost:5000/swagger/oauth2-redirect.html"),
                    new Uri("https://localhost:5001/swagger/oauth2-redirect.html"),
                    new Uri("https://localhost:7000/swagger/oauth2-redirect.html"),
                    // Add production API URLs here
                    // new Uri("https://api.smartskor.com/swagger/oauth2-redirect.html")
                },
                Permissions =
                {
                    // Endpoints
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    
                    // Grant types
                    Permissions.GrantTypes.AuthorizationCode,
                    
                    // Response types
                    Permissions.ResponseTypes.Code,
                    
                    // Scopes
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Prefixes.Scope + "smartskor-api"
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
    }
}