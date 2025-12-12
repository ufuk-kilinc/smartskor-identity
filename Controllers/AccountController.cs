using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;
using SmartSkor.Identity.Server.Models;
using SmartSkor.Identity.Server.Services;
using SmartSkor.Identity.Server.ViewModels;
using System.Security.Claims;
using System.Text.Json;

namespace SmartSkor.Identity.Server.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IStringLocalizer<AccountController> _localizer;
    private readonly IEmailService _emailService;
    private readonly RegistrationSettings _registrationSettings;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IStringLocalizer<AccountController> localizer,
        IEmailService emailService,
        IOptions<RegistrationSettings> registrationSettings,
        ILogger<AccountController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _localizer = localizer;
        _emailService = emailService;
        _registrationSettings = registrationSettings.Value;
        _logger = logger;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null, string? culture = null, string? theme = null)
    {
        // Check query params first, then TempData, then cookies (set by AuthorizationController)
        culture ??= TempData["TransferCulture"] as string;
        theme ??= TempData["TransferTheme"] as string;

        // Read from cookies set by AuthorizationController
        if (string.IsNullOrEmpty(culture))
        {
            var cultureCookie = Request.Cookies[CookieRequestCultureProvider.DefaultCookieName];
            if (!string.IsNullOrEmpty(cultureCookie))
            {
                var parsedCulture = CookieRequestCultureProvider.ParseCookieValue(cultureCookie);
                culture = parsedCulture?.Cultures.FirstOrDefault().Value;
            }
        }
        theme ??= Request.Cookies["theme"];

        SetCultureAndThemeFromQuery(culture, theme);

        var model = RestoreFormData<LoginViewModel>() ?? new LoginViewModel();
        model.ReturnUrl = returnUrl ?? model.ReturnUrl;
        RestoreModelState();
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid)
        {
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, _localizer["InvalidCredentials"]);
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
        }

        // Check if email is confirmed
        if (!user.EmailConfirmed)
        {
            ModelState.AddModelError(string.Empty, _localizer["EmailNotConfirmed"]);
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
        }

        var result = await _signInManager.PasswordSignInAsync(
            user,
            model.Password,
            model.RememberMe,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("User {Email} logged in.", model.Email);

            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                if (Url.IsLocalUrl(model.ReturnUrl) || IsAllowedRedirectUrl(model.ReturnUrl))
                {
                    return Redirect(AppendCultureAndThemeToUrl(model.ReturnUrl));
                }
            }

            return RedirectToAction("Index", "Home");
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToAction(nameof(LoginWith2fa), new { model.ReturnUrl, model.RememberMe });
        }

        if (result.IsLockedOut)
        {
            _logger.LogWarning("User {Email} account locked out.", model.Email);
            ModelState.AddModelError(string.Empty, _localizer["AccountLocked"]);
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
        }

        ModelState.AddModelError(string.Empty, _localizer["InvalidCredentials"]);
        StoreModelState();
        StoreFormData(model);
        return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register(string? returnUrl = null, string? culture = null, string? theme = null)
    {
        SetCultureAndThemeFromQuery(culture, theme);

        if (_registrationSettings.Mode == RegistrationMode.DeferredPassword)
        {
            return RedirectToAction(nameof(RegisterDeferred), new { returnUrl });
        }

        var model = RestoreFormData<RegisterViewModel>() ?? new RegisterViewModel();
        model.ReturnUrl = returnUrl ?? model.ReturnUrl;
        RestoreModelState();
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        // If in deferred mode, redirect
        if (_registrationSettings.Mode == RegistrationMode.DeferredPassword)
        {
            return RedirectToAction(nameof(RegisterDeferred), new { returnUrl = model.ReturnUrl });
        }

        if (!ModelState.IsValid)
        {
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Register), new { returnUrl = model.ReturnUrl });
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            if (!existingUser.EmailConfirmed)
            {
                // User exists but hasn't confirmed - resend confirmation email
                await SendConfirmationEmailAsync(existingUser, model.ReturnUrl);
                ViewData["Email"] = model.Email;
                ViewData["ReturnUrl"] = model.ReturnUrl;
                return View("RegisterConfirmation");
            }

            ModelState.AddModelError(string.Empty, _localizer["EmailAlreadyExists"]);
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(Register), new { returnUrl = model.ReturnUrl });
        }

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} created a new account. Confirmation email being sent.", model.Email);

            await SendConfirmationEmailAsync(user, model.ReturnUrl);

            ViewData["Email"] = model.Email;
            ViewData["ReturnUrl"] = model.ReturnUrl;
            return View("RegisterConfirmation");
        }

        foreach (var error in result.Errors)
        {
            if (!error.Code.Contains("UserName") && !error.Code.Contains("DuplicateEmail"))
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        if (ModelState.ErrorCount == 0)
        {
            ModelState.AddModelError(string.Empty, _localizer["RegistrationFailed"]);
        }

        StoreModelState();
        StoreFormData(model);
        return RedirectToAction(nameof(Register), new { returnUrl = model.ReturnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult RegisterDeferred(string? returnUrl = null, string? culture = null, string? theme = null)
    {
        SetCultureAndThemeFromQuery(culture, theme);

        var model = RestoreFormData<RegisterDeferredViewModel>() ?? new RegisterDeferredViewModel();
        model.ReturnUrl = returnUrl ?? model.ReturnUrl;
        RestoreModelState();
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterDeferred(RegisterDeferredViewModel model)
    {
        if (!ModelState.IsValid)
        {
            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(RegisterDeferred), new { returnUrl = model.ReturnUrl });
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            if (existingUser.EmailConfirmed)
            {
                ModelState.AddModelError(string.Empty, _localizer["EmailAlreadyExists"]);
            }
            else
            {
                // User exists but hasn't verified - resend verification email
                await SendVerificationEmailAsync(existingUser, model.ReturnUrl);
                ViewData["Email"] = model.Email;
                return View("RegisterConfirmation");
            }

            StoreModelState();
            StoreFormData(model);
            return RedirectToAction(nameof(RegisterDeferred), new { returnUrl = model.ReturnUrl });
        }

        // Create user without password
        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            EmailConfirmed = false
        };

        var result = await _userManager.CreateAsync(user);

        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} registered. Verification email being sent.", model.Email);

            await SendVerificationEmailAsync(user, model.ReturnUrl);

            ViewData["Email"] = model.Email;
            return View("RegisterConfirmation");
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        StoreModelState();
        StoreFormData(model);
        return RedirectToAction(nameof(RegisterDeferred), new { returnUrl = model.ReturnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult RegisterConfirmation()
    {
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResendVerificationEmail(string email, string? returnUrl = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null && !user.EmailConfirmed)
        {
            if (_registrationSettings.Mode == RegistrationMode.DeferredPassword && user.PasswordHash == null)
            {
                await SendVerificationEmailAsync(user, returnUrl);
            }
            else
            {
                await SendConfirmationEmailAsync(user, returnUrl);
            }
        }

        ViewData["Email"] = email;
        ViewData["ReturnUrl"] = returnUrl;
        return View("RegisterConfirmation");
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> SetPassword(string? email = null, string? code = null, string? returnUrl = null)
    {
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(email))
        {
            return BadRequest("Email and code must be supplied.");
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        if (user.EmailConfirmed && user.PasswordHash != null)
        {
            ModelState.AddModelError(string.Empty, _localizer["AccountAlreadyVerified"]);
            StoreModelState();
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var model = new SetPasswordViewModel
        {
            Email = email,
            Code = code
        };

        ViewData["ReturnUrl"] = returnUrl;
        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model, string? returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var isValidToken = await _userManager.VerifyUserTokenAsync(
            user,
            _userManager.Options.Tokens.EmailConfirmationTokenProvider,
            "EmailConfirmation",
            model.Code);

        if (!isValidToken)
        {
            ModelState.AddModelError(string.Empty, _localizer["InvalidVerificationToken"]);
            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Password);
        if (!addPasswordResult.Succeeded)
        {
            foreach (var error in addPasswordResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(model);
        }

        user.EmailConfirmed = true;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("User {Email} verified email and set password.", model.Email);

        await _signInManager.SignInAsync(user, isPersistent: false);
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // At the end of SetPassword POST, after signing in the user
        if (!string.IsNullOrEmpty(returnUrl) && IsAllowedRedirectUrl(returnUrl))
        {
            return Redirect(returnUrl);
        }

        // Default: redirect to login with returnUrl so user can complete OIDC flow
        return RedirectToAction(nameof(Login), new { returnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string? email = null, string? code = null, string? returnUrl = null)
    {
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
        {
            return BadRequest("Email and code must be supplied.");
        }

        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        if (user.EmailConfirmed)
        {
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var result = await _userManager.ConfirmEmailAsync(user, code);
        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} confirmed their email.", email);
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        ModelState.AddModelError(string.Empty, _localizer["InvalidVerificationToken"]);
        StoreModelState();
        return RedirectToAction(nameof(Login), new { returnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult LoginWith2fa(bool rememberMe, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        ViewData["RememberMe"] = rememberMe;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        _logger.LogInformation("User logged out.");
        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(string provider, string? returnUrl = null)
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");

        if (remoteError != null)
        {
            ModelState.AddModelError(string.Empty, _localizer["ExternalLoginError"]);
            StoreModelState();
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            ModelState.AddModelError(string.Empty, _localizer["ExternalLoginError"]);
            StoreModelState();
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        // Sign in the user with this external login provider if the user already has a login
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

        if (result.Succeeded)
        {
            _logger.LogInformation("User logged in with {Provider} provider.", info.LoginProvider);

            // Update last login time
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user != null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }

            return RedirectToReturnUrl(returnUrl);
        }

        if (result.IsLockedOut)
        {
            return View("Lockout");
        }

        // If the user does not have an account, create one
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "";
        var lastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "";

        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError(string.Empty, _localizer["ExternalLoginNoEmail"]);
            StoreModelState();
            return RedirectToAction(nameof(Login), new { returnUrl });
        }

        // Check if user with this email already exists
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null)
        {
            // Link the external login to existing account
            var addLoginResult = await _userManager.AddLoginAsync(existingUser, info);
            if (addLoginResult.Succeeded)
            {
                // Confirm email if not already (Google verified it)
                if (!existingUser.EmailConfirmed)
                {
                    existingUser.EmailConfirmed = true;
                }

                await _signInManager.SignInAsync(existingUser, isPersistent: false);
                existingUser.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(existingUser);

                _logger.LogInformation("Linked {Provider} to existing user {Email}.", info.LoginProvider, email);

                return RedirectToReturnUrl(returnUrl);
            }
        }

        // Create a new user
        var newUser = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            EmailConfirmed = true // Email is confirmed by Google
        };

        var createResult = await _userManager.CreateAsync(newUser);
        if (createResult.Succeeded)
        {
            var addLoginResult = await _userManager.AddLoginAsync(newUser, info);
            if (addLoginResult.Succeeded)
            {
                await _signInManager.SignInAsync(newUser, isPersistent: false);
                newUser.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(newUser);

                _logger.LogInformation("User {Email} created an account using {Provider}.", email, info.LoginProvider);

                return RedirectToReturnUrl(returnUrl);
            }
        }

        foreach (var error in createResult.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }

        StoreModelState();
        return RedirectToAction(nameof(Login), new { returnUrl });
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View(new ForgotPasswordViewModel());
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }

        var code = await _userManager.GeneratePasswordResetTokenAsync(user);
        var callbackUrl = Url.Action(
            nameof(ResetPassword),
            "Account",
            new { email = user.Email, code },
            protocol: HttpContext.Request.Scheme);

        // Get current culture for email language
        var culture = HttpContext.Features.Get<IRequestCultureFeature>();
        var language = culture?.RequestCulture?.UICulture?.Name ?? "en";

        try
        {
            await _emailService.SendPasswordResetEmailAsync(user.Email!, callbackUrl!, language);
            _logger.LogInformation("Password reset email sent to {Email}", model.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset email to {Email}", model.Email);
            // Still redirect to confirmation to not reveal if user exists
        }

        return RedirectToAction(nameof(ForgotPasswordConfirmation));
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? email = null, string? code = null)
    {
        if (code == null)
        {
            return BadRequest("A code must be supplied for password reset.");
        }

        var model = new ResetPasswordViewModel
        {
            Email = email ?? string.Empty,
            Code = code
        };

        return View(model);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
        if (result.Succeeded)
        {
            _logger.LogInformation("User {Email} reset their password.", model.Email);
            return RedirectToAction(nameof(ResetPasswordConfirmation));
        }

        foreach (var error in result.Errors)
        {
            if (error.Code == "InvalidToken")
            {
                ModelState.AddModelError(string.Empty, _localizer["InvalidResetToken"]);
            }
            else
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }

    #region Private Helper Methods

    private void SetCultureAndThemeFromQuery(string? culture, string? theme)
    {
        // Handle potential comma-separated values - take only the first
        var effectiveCulture = (culture ?? Request.Cookies["transfer_locale"])?.Split(',').FirstOrDefault();
        var effectiveTheme = (theme ?? Request.Cookies["transfer_theme"])?.Split(',').FirstOrDefault();

        if (!string.IsNullOrEmpty(effectiveCulture))
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(effectiveCulture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1), IsEssential = true }
            );
            Response.Cookies.Delete("transfer_locale");
        }

        if (!string.IsNullOrEmpty(effectiveTheme))
        {
            Response.Cookies.Append(
                "theme",
                effectiveTheme,
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1), IsEssential = true }
            );
            Response.Cookies.Delete("transfer_theme");

            // Pass to view for immediate application
            ViewData["ImmediateTheme"] = effectiveTheme;
        }
    }

    private void SetCultureFromQuery(string? culture)
    {
        if (!string.IsNullOrEmpty(culture))
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1), IsEssential = true }
            );
        }
    }

    private string AppendCultureAndThemeToUrl(string url)
    {
        var culture = HttpContext.Features.Get<IRequestCultureFeature>();
        var currentCulture = culture?.RequestCulture?.UICulture?.Name ?? "en";
        var currentTheme = Request.Cookies["theme"] ?? "system";

        var separator = url.Contains("?") ? "&" : "?";
        return $"{url}{separator}culture={currentCulture}&theme={currentTheme}";
    }

    private IActionResult RedirectToReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl))
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(AppendCultureAndThemeToUrl(returnUrl));
            }

            if (IsAllowedRedirectUrl(returnUrl))
            {
                return Redirect(AppendCultureAndThemeToUrl(returnUrl));
            }
        }

        return RedirectToAction("Index", "Home");
    }

    private async Task SendVerificationEmailAsync(ApplicationUser user, string? returnUrl = null)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action(
            nameof(SetPassword),
            "Account",
            new { email = user.Email, code, returnUrl },
            protocol: HttpContext.Request.Scheme);

        var culture = HttpContext.Features.Get<IRequestCultureFeature>();
        var language = culture?.RequestCulture?.UICulture?.Name ?? "en";

        try
        {
            await _emailService.SendEmailVerificationAsync(user.Email!, callbackUrl!, user.FirstName, language);
            _logger.LogInformation("Verification email sent to {Email}", user.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send verification email to {Email}", user.Email);
        }
    }

    private async Task SendConfirmationEmailAsync(ApplicationUser user, string? returnUrl = null)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action(
            nameof(ConfirmEmail),
            "Account",
            new { email = user.Email, code, returnUrl },
            protocol: HttpContext.Request.Scheme);

        var culture = HttpContext.Features.Get<IRequestCultureFeature>();
        var language = culture?.RequestCulture?.UICulture?.Name ?? "en";

        try
        {
            await _emailService.SendEmailConfirmationAsync(user.Email!, callbackUrl!, user.FirstName, language);
            _logger.LogInformation("Confirmation email sent to {Email}", user.Email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send confirmation email to {Email}", user.Email);
        }
    }

    private void StoreModelState()
    {
        var errors = ModelState
            .Where(x => x.Value?.Errors.Count > 0)
            .ToDictionary(
                k => k.Key,
                v => v.Value!.Errors.Select(e => e.ErrorMessage).ToArray()
            );

        TempData["ModelStateErrors"] = JsonSerializer.Serialize(errors);
    }

    private void RestoreModelState()
    {
        if (TempData["ModelStateErrors"] is string json)
        {
            var errors = JsonSerializer.Deserialize<Dictionary<string, string[]>>(json);
            if (errors != null)
            {
                foreach (var error in errors)
                {
                    foreach (var message in error.Value)
                    {
                        ModelState.AddModelError(error.Key, message);
                    }
                }
            }
        }
    }

    private void StoreFormData<T>(T model)
    {
        // Clear passwords before storing
        if (model is LoginViewModel loginModel)
        {
            loginModel.Password = string.Empty;
        }
        else if (model is RegisterViewModel registerModel)
        {
            registerModel.Password = string.Empty;
            registerModel.ConfirmPassword = string.Empty;
        }

        TempData["FormData"] = JsonSerializer.Serialize(model);
    }

    private T? RestoreFormData<T>() where T : class
    {
        if (TempData["FormData"] is string json)
        {
            return JsonSerializer.Deserialize<T>(json);
        }
        return null;
    }

    private bool IsAllowedRedirectUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        try
        {
            var uri = new Uri(url);
            var allowedHosts = new[] { "localhost", "127.0.0.1", "smartskor.com", "www.smartskor.com" };
            return allowedHosts.Any(host => uri.Host.Equals(host, StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            return false;
        }
    }

    #endregion
}