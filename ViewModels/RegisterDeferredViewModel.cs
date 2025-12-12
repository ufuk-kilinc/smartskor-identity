using System.ComponentModel.DataAnnotations;

namespace SmartSkor.Identity.Server.ViewModels;

public class RegisterDeferredViewModel
{
    [Required(ErrorMessage = "FirstNameRequired")]
    [Display(Name = "FirstName")]
    public string FirstName { get; set; } = string.Empty;

    [Required(ErrorMessage = "LastNameRequired")]
    [Display(Name = "LastName")]
    public string LastName { get; set; } = string.Empty;

    [Required(ErrorMessage = "EmailRequired")]
    [EmailAddress(ErrorMessage = "EmailInvalid")]
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}