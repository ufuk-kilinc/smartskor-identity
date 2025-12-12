using System.ComponentModel.DataAnnotations;

namespace SmartSkor.Identity.Server.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "EmailRequired")]
    [EmailAddress(ErrorMessage = "EmailInvalid")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "PasswordRequired")]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "RememberMe")]
    public bool RememberMe { get; set; }

    public string? ReturnUrl { get; set; }
}