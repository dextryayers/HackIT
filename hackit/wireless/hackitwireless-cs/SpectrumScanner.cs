using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace HackItWireless
{
    public readonly struct ChannelInfo
    {
        public int Number { get; }
        public int Frequency { get; }
        public string Band { get; }
        public int ApCount { get; }
        public int Rssi { get; }
        public double Utilization { get; }

        public ChannelInfo(int number, int frequency, string band, int apCount, int rssi, double utilization)
        {
            Number = number;
            Frequency = frequency;
            Band = band;
            ApCount = apCount;
            Rssi = rssi;
            Utilization = utilization;
        }

        public override string ToString() =>
            $"Ch {Number:D2} ({Frequency}MHz, {Band}) APs={ApCount} RSSI={Rssi} Util={Utilization:P1}";
    }

    public sealed class SpectrumScanner
    {
        private static readonly int[] Channel2Ghz = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
        private static readonly int[] Channel5Ghz = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 };

        private static Dictionary<int, int> ChannelFrequencyMap => Enumerable.Range(1, 14)
            .ToDictionary(c => c, c => 2412 + (c - 1) * 5)
            .Concat(new Dictionary<int, int>
            {
                { 36, 5180 }, { 40, 5200 }, { 44, 5220 }, { 48, 5240 },
                { 52, 5260 }, { 56, 5280 }, { 60, 5300 }, { 64, 5320 },
                { 100, 5500 }, { 104, 5520 }, { 108, 5540 }, { 112, 5560 },
                { 116, 5580 }, { 120, 5600 }, { 124, 5620 }, { 128, 5640 },
                { 132, 5660 }, { 136, 5680 }, { 140, 5700 }, { 144, 5720 },
                { 149, 5745 }, { 153, 5765 }, { 157, 5785 }, { 161, 5805 }, { 165, 5825 },
            }).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        public async Task<List<ChannelInfo>> ScanAllChannels(string interfaceName)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));

            var allChannels = new List<int>();
            allChannels.AddRange(Channel2Ghz);
            allChannels.AddRange(Channel5Ghz);

            var utilization = await MeasureChannelUtilization(interfaceName, allChannels.ToArray()).ConfigureAwait(false);

            var results = new List<ChannelInfo>();
            foreach (var kvp in utilization)
            {
                int ch = kvp.Key;
                int freq = ChannelFrequencyMap.GetValueOrDefault(ch, 0);
                string band = ch <= 14 ? "2.4 GHz" : "5 GHz";
                int rssi = await MeasureRssi(interfaceName, ch).ConfigureAwait(false);
                double util = CalculateUtilization(kvp.Value, 1);

                results.Add(new ChannelInfo(ch, freq, band, kvp.Value, rssi, util));
            }

            return results.OrderBy(c => c.Number).ToList();
        }

        public ChannelInfo FindBestChannel(List<ChannelInfo> channels)
        {
            if (channels == null || channels.Count == 0)
                throw new ArgumentException("Channel list cannot be null or empty.", nameof(channels));

            return channels
                .OrderBy(c => c.Utilization)
                .ThenBy(c => c.ApCount)
                .ThenByDescending(c => c.Rssi)
                .First();
        }

        public async Task<Dictionary<int, int>> MeasureChannelUtilization(string interfaceName, int[] channels)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (channels == null || channels.Length == 0)
                throw new ArgumentException("Channel list cannot be null or empty.", nameof(channels));

            var results = new Dictionary<int, int>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                foreach (int ch in channels)
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "netsh",
                        Arguments = $"wlan show networks mode=bssid interface=\"{interfaceName}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    };

                    using var proc = Process.Start(psi);
                    if (proc == null) continue;

                    string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                    await proc.WaitForExitAsync().ConfigureAwait(false);

                    int count = 0;
                    var channelMatches = Regex.Matches(output,
                        $@"Channel\s*:\s*{ch}\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                    count = channelMatches.Count;

                    var bssidMatches = Regex.Matches(output,
                        @"BSSID\s*\d+\s*:\s*([0-9A-Fa-f:]{17})", RegexOptions.Multiline);
                    foreach (Match bm in bssidMatches)
                    {
                        int bssidLine = output.Substring(0, bm.Index).Count(c => c == '\n');
                        string contextStart = output.Split('\n').Skip(bssidLine).FirstOrDefault() ?? "";
                        if (Regex.IsMatch(contextStart, $@"Channel\s*:\s*{ch}"))
                            count++;
                    }

                    results[ch] = count;
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "iw",
                    Arguments = $"dev \"{interfaceName}\" scan",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                    await proc.WaitForExitAsync().ConfigureAwait(false);

                    foreach (int ch in channels)
                    {
                        int count = Regex.Matches(output,
                            $@"freq:\s*{ChannelFrequencyMap.GetValueOrDefault(ch, 0)}",
                            RegexOptions.Multiline).Count;
                        results[ch] = count;
                    }
                }
            }
            else
            {
                throw new PlatformNotSupportedException(
                    "Channel scanning is only supported on Windows and Linux.");
            }

            return results;
        }

        private static async Task<int> MeasureRssi(string interfaceName, int channel)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"wlan show interfaces",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null) return -100;

                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                var match = Regex.Match(output, @"Signal\s*:\s*(\d+)%");
                if (match.Success)
                {
                    int percent = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                    return (int)Math.Round((percent / 100.0) * 60 - 100);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "iw",
                    Arguments = $"dev \"{interfaceName}\" link",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null) return -100;

                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                var match = Regex.Match(output, @"signal:\s*(-?\d+)");
                if (match.Success)
                    return int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            }

            return -100;
        }

        private static double CalculateUtilization(int apCount, double scanTimeSeconds)
        {
            double baseUtil = apCount * 0.05;
            double airtimeFactor = Math.Min(apCount * 0.1, 0.9);
            return Math.Min(baseUtil + airtimeFactor, 1.0);
        }
    }
}
