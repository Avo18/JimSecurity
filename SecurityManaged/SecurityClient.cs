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
        public bool SendPublicKey(string privateKey)
        {
            return Native.SendPublicKeyToDriver(privateKey);
        }
        public bool SendPublicKeyFromFile(string fileName, string mode)
        {
            return Native.SendPublicKeyToDriver(fileName, mode);
        }
    }
}
