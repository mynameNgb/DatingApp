using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserForRegisterDto
    {
        [Required]
        public string Username { get; set; }
        [Required]
        [StringLength(8,MinimumLength = 4, ErrorMessage = "You must specify a password beetwen 4 - 8 characters")]
        public string Password { get; set; }
    }
}