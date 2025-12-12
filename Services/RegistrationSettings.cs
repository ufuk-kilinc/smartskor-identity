namespace SmartSkor.Identity.Server.Services;

public class RegistrationSettings
{
    public RegistrationMode Mode { get; set; } = RegistrationMode.Immediate;
}

public enum RegistrationMode
{
    /// <summary>
    /// User creates password during registration, can log in immediately.
    /// No email verification required.
    /// </summary>
    Immediate,

    /// <summary>
    /// User only provides name and email during registration.
    /// Verification email sent with link to set password.
    /// Email confirmed when password is set.
    /// </summary>
    DeferredPassword
}