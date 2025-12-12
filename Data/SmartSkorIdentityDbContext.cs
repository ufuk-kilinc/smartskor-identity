using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SmartSkor.Identity.Server.Models;

namespace SmartSkor.Identity.Server.Data;

public class SmartSkorIdentityDbContext : IdentityDbContext<ApplicationUser>
{
    public SmartSkorIdentityDbContext(DbContextOptions<SmartSkorIdentityDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.FirstName).HasMaxLength(100);
            entity.Property(e => e.LastName).HasMaxLength(100);
        });
    }
}