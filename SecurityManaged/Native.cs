namespace SecurityManaged
{
    using System.Runtime.InteropServices;
    using System;

    internal static class Native
    {
        [DllImport("Security.Native.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool Connect();

        [DllImport("Security.Native.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool Authenticate();

        [DllImport("Security.Native.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool Ping();

        [DllImport("Security.Native.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool SendPrivateKeyToDriver(string privateKey);
        [DllImport("Security.Native.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern bool SendPrivateKeyToDriver(string fileName, string mode);
    }
}
