namespace SmartSkor.Identity.Server.Services;

public interface IEmailService
{
    Task SendPasswordResetEmailAsync(string toEmail, string resetLink, string language);
    Task SendEmailVerificationAsync(string toEmail, string verificationLink, string firstName, string language);
    Task SendEmailConfirmationAsync(string toEmail, string confirmationLink, string firstName, string language);
}