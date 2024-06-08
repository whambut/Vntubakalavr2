using System.Threading.Tasks;
using UserAuthApi.Models;

namespace UserAuthApi.Services
{
    public interface IAuthService
    {
        Task<string> Register(User user, string password);
        Task<LoginResponse> Login(string email, string password);
        Task<bool> UserExists(string username);
    }
}