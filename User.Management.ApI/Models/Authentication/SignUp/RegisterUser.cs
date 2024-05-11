using System.ComponentModel.DataAnnotations;

namespace User.Management.ApI.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage ="User name is requires")]
        public string UserName { get; set; }
        [EmailAddress]
        [Required(ErrorMessage = "Email is requires")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Password  is requires")]
        public string Password { get; set; }
    }
}
