namespace SmartSkor.Identity.Server.Extensions;

public static class GoogleAuthExtensions
{
    public static IServiceCollection AddGoogleAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication()
            .AddGoogle(options =>
            {
                options.ClientId = configuration["Authentication:Google:ClientId"]!;
                options.ClientSecret = configuration["Authentication:Google:ClientSecret"]!;
                options.CallbackPath = "/signin-google";
                options.Scope.Add("profile");
                options.Scope.Add("email");
            });

        return services;
    }
}