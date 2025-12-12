using Microsoft.AspNetCore.Identity;
using SmartSkor.Identity.Server.Data;
using SmartSkor.Identity.Server.Models;
using SmartSkor.Identity.Server.Services;

namespace SmartSkor.Identity.Server.Extensions;

public static class IdentityExtensions
{
    public static IServiceCollection AddIdentityServices(this IServiceCollection services)
    {
        services.AddIdentity<ApplicationUser, IdentityRole>(options =>
        {
            // Password settings
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireUppercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequiredLength = 8;

            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;

            // User settings
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = false;
        })
        .AddEntityFrameworkStores<SmartSkorIdentityDbContext>()
        .AddDefaultTokenProviders()
        .AddErrorDescriber<LocalizedIdentityErrorDescriber>();

        return services;
    }
}