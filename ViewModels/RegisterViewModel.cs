using System.ComponentModel.DataAnnotations;

namespace SmartSkor.Identity.Server.ViewModels;

public class RegisterViewModel
{
    [Required(ErrorMessage = "FirstNameRequired")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "FirstNameLength")]
    [Display(Name = "FirstName")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "LastNameRequired")]
    [StringLength(100, MinimumLength = 2, ErrorMessage = "LastNameLength")]
    [Display(Name = "LastName")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "EmailRequired")]
    [EmailAddress(ErrorMessage = "EmailInvalid")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "PasswordRequired")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "PasswordLength")]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "ConfirmPasswordRequired")]
    [Compare("Password", ErrorMessage = "PasswordsMustMatch")]
    [DataType(DataType.Password)]
    [Display(Name = "ConfirmPassword")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}