using Microsoft.EntityFrameworkCore;
using SmartSkor.Identity.Server.Data;
using SmartSkor.Identity.Server.Extensions;
using SmartSkor.Identity.Server.Services;

var builder = WebApplication.CreateBuilder(args);

// Localization (must come before AddControllersWithViews)
builder.Services.AddLocalizationServices();

// Email Service
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddTransient<IEmailService, EmailService>();

// Registration Settings
builder.Services.Configure<RegistrationSettings>(builder.Configuration.GetSection("RegistrationSettings"));

// Database
builder.Services.AddDbContext<SmartSkorIdentityDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

// Identity
builder.Services.AddIdentityServices();

// Google Authentication
builder.Services.AddGoogleAuthentication(builder.Configuration);

// Authorization
builder.Services.AddAuthorization();

// OpenIddict
builder.Services.AddOpenIddictServer();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Localization middleware
app.UseRequestLocalization();
app.UseCultureCookie();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seed database
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<SmartSkorIdentityDbContext>();
    await context.Database.MigrateAsync();
    await SeedData.InitializeAsync(scope.ServiceProvider);
}

app.Run();