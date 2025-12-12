using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Retry;

namespace SmartSkor.Identity.Server.Services;

public class EmailService : IEmailService
{
    private readonly SmtpSettings _smtpSettings;
    private readonly ILogger<EmailService> _logger;
    private readonly AsyncRetryPolicy _retryPolicy;

    public EmailService(IOptions<SmtpSettings> smtpSettings, ILogger<EmailService> logger)
    {
        _smtpSettings = smtpSettings.Value;
        _logger = logger;

        // Retry 3 times with exponential backoff: 2s, 4s, 8s
        _retryPolicy = Policy
            .Handle<SmtpException>()
            .Or<IOException>()
            .Or<TimeoutException>()
            .WaitAndRetryAsync(
                retryCount: 3,
                sleepDurationProvider: attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)),
                onRetry: (exception, timeSpan, retryCount, context) =>
                {
                    _logger.LogWarning(
                        exception,
                        "Email send attempt {RetryCount} failed. Waiting {TimeSpan} before next retry.",
                        retryCount,
                        timeSpan);
                });
    }

    public async Task SendPasswordResetEmailAsync(string toEmail, string resetLink, string language)
    {
        var subject = language.StartsWith("tr")
            ? "SmartSkor - Şifre Sıfırlama"
            : "SmartSkor - Password Reset";

        var body = language.StartsWith("tr")
            ? GetTurkishEmailTemplate(resetLink)
            : GetEnglishEmailTemplate(resetLink);

        await SendEmailWithRetryAsync(toEmail, subject, body);
    }

    public async Task SendEmailVerificationAsync(string toEmail, string verificationLink, string firstName, string language)
    {
        var subject = language.StartsWith("tr")
            ? "SmartSkor - Hesabınızı Doğrulayın"
            : "SmartSkor - Verify Your Account";

        var body = language.StartsWith("tr")
            ? GetTurkishVerificationEmailTemplate(verificationLink, firstName)
            : GetEnglishVerificationEmailTemplate(verificationLink, firstName);

        await SendEmailWithRetryAsync(toEmail, subject, body);
    }

    public async Task SendEmailConfirmationAsync(string toEmail, string confirmationLink, string firstName, string language)
    {
        var subject = language.StartsWith("tr")
            ? "SmartSkor - E-postanızı Doğrulayın"
            : "SmartSkor - Confirm Your Email";

        var body = language.StartsWith("tr")
            ? GetTurkishConfirmationEmailTemplate(confirmationLink, firstName)
            : GetEnglishConfirmationEmailTemplate(confirmationLink, firstName);

        await SendEmailWithRetryAsync(toEmail, subject, body);
    }

    private string GetEnglishConfirmationEmailTemplate(string confirmationLink, string firstName)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Welcome, {firstName}!</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                Thank you for registering with SmartSkor. Please click the button below to confirm your email address and activate your account.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{confirmationLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>Confirm Email</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                This link will expire in 24 hours. If you didn't create an account with SmartSkor, you can safely ignore this email.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href='{confirmationLink}' style='color: #319795; word-break: break-all;'>{confirmationLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetTurkishConfirmationEmailTemplate(string confirmationLink, string firstName)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Hoş geldiniz, {firstName}!</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                SmartSkor'a kaydolduğunuz için teşekkür ederiz. Hesabınızı etkinleştirmek için lütfen aşağıdaki butona tıklayarak e-posta adresinizi doğrulayın.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{confirmationLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>E-postayı Doğrula</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                Bu bağlantı 24 saat içinde geçerliliğini yitirecektir. SmartSkor'da hesap oluşturmadıysanız, bu e-postayı güvenle görmezden gelebilirsiniz.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                Buton çalışmıyorsa, bu bağlantıyı kopyalayıp tarayıcınıza yapıştırın:<br>
                <a href='{confirmationLink}' style='color: #319795; word-break: break-all;'>{confirmationLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetEnglishVerificationEmailTemplate(string verificationLink, string firstName)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Welcome, {firstName}!</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                Thank you for registering with SmartSkor. To complete your account setup, please click the button below to verify your email and set your password.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{verificationLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>Verify & Set Password</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                This link will expire in 24 hours. If you didn't create an account with SmartSkor, you can safely ignore this email.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href='{verificationLink}' style='color: #319795; word-break: break-all;'>{verificationLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetTurkishVerificationEmailTemplate(string verificationLink, string firstName)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Hoş geldiniz, {firstName}!</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                SmartSkor'a kaydolduğunuz için teşekkür ederiz. Hesap kurulumunuzu tamamlamak için lütfen aşağıdaki butona tıklayarak e-postanızı doğrulayın ve şifrenizi belirleyin.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{verificationLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>Doğrula ve Şifre Belirle</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                Bu bağlantı 24 saat içinde geçerliliğini yitirecektir. SmartSkor'da hesap oluşturmadıysanız, bu e-postayı güvenle görmezden gelebilirsiniz.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                Buton çalışmıyorsa, bu bağlantıyı kopyalayıp tarayıcınıza yapıştırın:<br>
                <a href='{verificationLink}' style='color: #319795; word-break: break-all;'>{verificationLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }

    private async Task SendEmailWithRetryAsync(string toEmail, string subject, string body)
    {
        try
        {
            await _retryPolicy.ExecuteAsync(async () =>
            {
                await SendEmailAsync(toEmail, subject, body);
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to send email to {Email} after all retry attempts.",
                toEmail);
            throw;
        }
    }

    private async Task SendEmailAsync(string toEmail, string subject, string body)
    {
        using var client = new SmtpClient(_smtpSettings.Host, _smtpSettings.Port)
        {
            Credentials = new NetworkCredential(_smtpSettings.UserName, _smtpSettings.Password),
            EnableSsl = _smtpSettings.EnableSsl,
            Timeout = 30000 // 30 seconds
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_smtpSettings.FromEmail, _smtpSettings.FromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = true
        };
        mailMessage.To.Add(toEmail);

        await client.SendMailAsync(mailMessage);
        _logger.LogInformation("Email sent successfully to {Email}", toEmail);
    }

    private string GetEnglishEmailTemplate(string resetLink)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Reset Your Password</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                We received a request to reset your password. Click the button below to create a new password. This link will expire in 24 hours.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{resetLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>Reset Password</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href='{resetLink}' style='color: #319795; word-break: break-all;'>{resetLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetTurkishEmailTemplate(string resetLink)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
</head>
<body style='margin: 0; padding: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif; background-color: #F7FAFC;'>
    <div style='max-width: 600px; margin: 0 auto; padding: 40px 20px;'>
        <div style='background-color: #FFFFFF; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
            <div style='text-align: center; margin-bottom: 30px;'>
                <h1 style='color: #319795; font-size: 28px; margin: 0;'>SmartSkor</h1>
            </div>
            
            <h2 style='color: #1A202C; font-size: 24px; margin-bottom: 16px; text-align: center;'>Şifrenizi Sıfırlayın</h2>
            
            <p style='color: #4A5568; font-size: 16px; line-height: 24px; margin-bottom: 24px;'>
                Şifrenizi sıfırlamak için bir talep aldık. Yeni bir şifre oluşturmak için aşağıdaki butona tıklayın. Bu bağlantı 24 saat içinde geçerliliğini yitirecektir.
            </p>
            
            <div style='text-align: center; margin-bottom: 24px;'>
                <a href='{resetLink}' style='display: inline-block; background-color: #319795; color: #FFFFFF; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 500; font-size: 16px;'>Şifreyi Sıfırla</a>
            </div>
            
            <p style='color: #718096; font-size: 14px; line-height: 20px; margin-bottom: 16px;'>
                Şifre sıfırlama talebinde bulunmadıysanız, bu e-postayı güvenle görmezden gelebilirsiniz. Şifreniz değişmeden kalacaktır.
            </p>
            
            <hr style='border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;'>
            
            <p style='color: #A0AEC0; font-size: 12px; line-height: 18px; text-align: center;'>
                Buton çalışmıyorsa, bu bağlantıyı kopyalayıp tarayıcınıza yapıştırın:<br>
                <a href='{resetLink}' style='color: #319795; word-break: break-all;'>{resetLink}</a>
            </p>
        </div>
    </div>
</body>
</html>";
    }
}