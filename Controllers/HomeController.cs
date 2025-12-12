using Microsoft.AspNetCore.Mvc;

namespace SmartSkor.Identity.Server.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}