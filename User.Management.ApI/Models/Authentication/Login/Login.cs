using System.ComponentModel.DataAnnotations;

namespace User.Management.ApI.Models.Authentication.Login
{
    public class Login
    {
        [Required(ErrorMessage ="User name is required")]
        public string? UserName { get; set; }
        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }
    }
}
