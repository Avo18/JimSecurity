using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityManaged
{
    public class SecurityClient
    {
        public bool Init()
        {
            return Native.Connect() && Native.Authenticate();
        }

        public void SendPing()
        {
            Native.Ping();
        }
        public bool SendPrivateKey(string privateKey)
        {
            return Native.SendPrivateKeyToDriver(privateKey);
        }
        public bool SendPrivateKeyFromFile(string fileName, string mode)
        {
            return Native.SendPrivateKeyToDriver(fileName, mode);
        }
    }
}
