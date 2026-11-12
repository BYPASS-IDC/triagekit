using System.Diagnostics;
using System.Security.Cryptography;
class Vuln {
  void Run(string user) {
    Process.Start("cmd.exe", "/c " + user);
  }
  void Hash(string pw) {
    MD5.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(pw));
  }
}
