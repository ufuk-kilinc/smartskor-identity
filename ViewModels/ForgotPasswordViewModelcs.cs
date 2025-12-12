using System.ComponentModel.DataAnnotations;

namespace SmartSkor.Identity.Server.ViewModels;

public class ForgotPasswordViewModel
{
    [Required(ErrorMessage = "EmailRequired")]
    [EmailAddress(ErrorMessage = "EmailInvalid")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;
}