using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;

namespace SmartSkor.Identity.Server.Services;

public class LocalizedIdentityErrorDescriber : IdentityErrorDescriber
{
    private readonly IStringLocalizer<LocalizedIdentityErrorDescriber> _localizer;

    public LocalizedIdentityErrorDescriber(IStringLocalizer<LocalizedIdentityErrorDescriber> localizer)
    {
        _localizer = localizer;
    }

    public override IdentityError DuplicateEmail(string email)
    {
        return new IdentityError
        {
            Code = nameof(DuplicateEmail),
            Description = _localizer["DuplicateEmail", email]
        };
    }

    public override IdentityError DuplicateUserName(string userName)
    {
        return new IdentityError
        {
            Code = nameof(DuplicateUserName),
            Description = _localizer["DuplicateUserName", userName]
        };
    }

    public override IdentityError InvalidEmail(string? email)
    {
        return new IdentityError
        {
            Code = nameof(InvalidEmail),
            Description = _localizer["InvalidEmail", email ?? ""]
        };
    }

    public override IdentityError PasswordMismatch()
    {
        return new IdentityError
        {
            Code = nameof(PasswordMismatch),
            Description = _localizer["PasswordMismatch"]
        };
    }

    public override IdentityError PasswordRequiresDigit()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresDigit),
            Description = _localizer["PasswordRequiresDigit"]
        };
    }

    public override IdentityError PasswordRequiresLower()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresLower),
            Description = _localizer["PasswordRequiresLower"]
        };
    }

    public override IdentityError PasswordRequiresNonAlphanumeric()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresNonAlphanumeric),
            Description = _localizer["PasswordRequiresNonAlphanumeric"]
        };
    }

    public override IdentityError PasswordRequiresUpper()
    {
        return new IdentityError
        {
            Code = nameof(PasswordRequiresUpper),
            Description = _localizer["PasswordRequiresUpper"]
        };
    }

    public override IdentityError PasswordTooShort(int length)
    {
        return new IdentityError
        {
            Code = nameof(PasswordTooShort),
            Description = _localizer["PasswordTooShort", length]
        };
    }

    public override IdentityError InvalidToken()
    {
        return new IdentityError
        {
            Code = nameof(InvalidToken),
            Description = _localizer["InvalidToken"]
        };
    }
}