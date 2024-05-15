using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace User.Management.ApI.Controllers
{
    [Authorize (Roles="Admin")]
    [Route("api/controller")]
    [ApiController]
    public class AdminController : ControllerBase
    {             
        [HttpGet("employees")]
        public IEnumerable<string> Get()
        {
            return new List<string> { "Nimuna","Manzoor","Anna" };
        }
    }
}
