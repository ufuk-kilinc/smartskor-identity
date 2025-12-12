using System.ComponentModel.DataAnnotations;

namespace SmartSkor.Identity.Server.ViewModels;

public class ResetPasswordViewModel
{
    [Required(ErrorMessage = "EmailRequired")]
    [EmailAddress(ErrorMessage = "EmailInvalid")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "PasswordRequired")]
    [StringLength(100, ErrorMessage = "PasswordLength", MinimumLength = 8)]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "ConfirmPasswordRequired")]
    [DataType(DataType.Password)]
    [Display(Name = "ConfirmPassword")]
    [Compare("Password", ErrorMessage = "PasswordsMustMatch")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;
}