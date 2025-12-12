using System.Globalization;
using Microsoft.AspNetCore.Localization;

namespace SmartSkor.Identity.Server.Extensions;

public static class LocalizationExtensions
{
    public static IServiceCollection AddLocalizationServices(this IServiceCollection services)
    {
        services.AddLocalization(options => options.ResourcesPath = "Resources");
        services.AddControllersWithViews()
            .AddViewLocalization()
            .AddDataAnnotationsLocalization();

        services.Configure<RequestLocalizationOptions>(options =>
        {
            var supportedCultures = new[]
            {
                new CultureInfo("en"),
                new CultureInfo("tr")
            };

            options.DefaultRequestCulture = new RequestCulture("en");
            options.SupportedCultures = supportedCultures;
            options.SupportedUICultures = supportedCultures;
            options.RequestCultureProviders = new List<IRequestCultureProvider>
            {
                new QueryStringRequestCultureProvider(),
                new CookieRequestCultureProvider()
            };
        });

        return services;
    }

    public static IApplicationBuilder UseCultureCookie(this IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            if (context.Request.Query.ContainsKey("culture"))
            {
                // Take only the first value in case of comma-separated values
                var culture = context.Request.Query["culture"].FirstOrDefault()?.Split(',').FirstOrDefault();

                if (!string.IsNullOrEmpty(culture))
                {
                    context.Response.Cookies.Append(
                        CookieRequestCultureProvider.DefaultCookieName,
                        CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                        new CookieOptions
                        {
                            Expires = DateTimeOffset.UtcNow.AddYears(1),
                            IsEssential = true
                        }
                    );
                }
            }

            await next();
        });

        return app;
    }
}