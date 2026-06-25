using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace HackItWireless
{
    public readonly struct ScanResult
    {
        public int Number { get; }
        public int Frequency { get; }
        public string Band { get; }
        public int ApCount { get; }
        public int Rssi { get; }
        public double Utilization { get; }

        public ScanResult(int number, int frequency, string band, int apCount, int rssi, double utilization)
        {
            Number = number; Frequency = frequency; Band = band;
            ApCount = apCount; Rssi = rssi; Utilization = utilization;
        }

        public override string ToString() =>
            $"Ch {Number:D2} ({Frequency}MHz, {Band}) APs={ApCount} RSSI={Rssi} Util={Utilization:P1}";
    }

    public sealed class SpectrumScanner
    {
        private static readonly int[] Channel2Ghz = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
        private static readonly int[] Channel5Ghz = { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 };

        private static readonly Dictionary<int, int> ChannelFrequencyMap = new()
        {
            { 1, 2412 }, { 2, 2417 }, { 3, 2422 }, { 4, 2427 }, { 5, 2432 },
            { 6, 2437 }, { 7, 2442 }, { 8, 2447 }, { 9, 2452 }, { 10, 2457 },
            { 11, 2462 }, { 12, 2467 }, { 13, 2472 }, { 14, 2484 },
            { 36, 5180 }, { 40, 5200 }, { 44, 5220 }, { 48, 5240 },
            { 52, 5260 }, { 56, 5280 }, { 60, 5300 }, { 64, 5320 },
            { 100, 5500 }, { 104, 5520 }, { 108, 5540 }, { 112, 5560 },
            { 116, 5580 }, { 120, 5600 }, { 124, 5620 }, { 128, 5640 },
            { 132, 5660 }, { 136, 5680 }, { 140, 5700 }, { 144, 5720 },
            { 149, 5745 }, { 153, 5765 }, { 157, 5785 }, { 161, 5805 }, { 165, 5825 },
        };

        public async Task<List<ScanResult>> ScanAllChannels(string interfaceName)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));

            var allChannels = new List<int>(Channel2Ghz.Length + Channel5Ghz.Length);
            allChannels.AddRange(Channel2Ghz);
            allChannels.AddRange(Channel5Ghz);

            var utilization = await MeasureChannelUtilization(interfaceName, allChannels.ToArray()).ConfigureAwait(false);

            var results = new List<ScanResult>(utilization.Count);
            foreach (var kvp in utilization)
            {
                int ch = kvp.Key;
                int freq = ChannelFrequencyMap.GetValueOrDefault(ch, 0);
                string band = ch <= 14 ? "2.4 GHz" : "5 GHz";
                int rssi = await MeasureRssi(interfaceName, ch).ConfigureAwait(false);
                double util = CalculateUtilization(kvp.Value, 1);
                results.Add(new ScanResult(ch, freq, band, kvp.Value, rssi, util));
            }

            results.Sort((a, b) => a.Number.CompareTo(b.Number));
            return results;
        }

        public ScanResult FindBestChannel(List<ScanResult> channels)
        {
            if (channels == null || channels.Count == 0)
                return default;

            ScanResult best = channels[0];
            for (int i = 1; i < channels.Count; i++)
            {
                var c = channels[i];
                if (c.ApCount < best.ApCount ||
                    (c.ApCount == best.ApCount && c.Utilization < best.Utilization) ||
                    (c.ApCount == best.ApCount && c.Utilization == best.Utilization && c.Rssi > best.Rssi))
                    best = c;
            }
            return best;
        }

        public async Task<Dictionary<int, int>> MeasureChannelUtilization(string interfaceName, int[] channels)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));
            if (channels == null || channels.Length == 0)
                throw new ArgumentException("Channel list cannot be null or empty.", nameof(channels));

            var results = new Dictionary<int, int>();
            var CH = new HashSet<int>(channels);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"wlan show networks mode=bssid interface=\"{interfaceName}\"",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null) return results;
                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                int currentCh = -1;
                foreach (string line in output.Split('\n'))
                {
                    int colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    string key = line.Substring(0, colon).Trim();
                    string val = line.Substring(colon + 1).Trim();
                    if (string.Equals(key, "Channel", StringComparison.OrdinalIgnoreCase) &&
                        int.TryParse(val, out int ch) && CH.Contains(ch))
                        currentCh = ch;
                    else if (key.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase) && currentCh > 0)
                        results[currentCh] = results.GetValueOrDefault(currentCh, 0) + 1;
                }
                foreach (int ch in channels)
                {
                    if (!results.ContainsKey(ch))
                        results[ch] = 0;
                    if (Is2GhzChannel(ch))
                    {
                        int rssi = await MeasureRssi(interfaceName, ch).ConfigureAwait(false);
                        results[ch] = Math.Max(results[ch], (int)Math.Round(CalculateUtilization(0, rssi)));
                    }
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "iw",
                    Arguments = $"dev {interfaceName} survey dump",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null) return results;
                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                int currentCh = -1;
                foreach (string line in output.Split('\n'))
                {
                    int colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    string key = line.Substring(0, colon).Trim();
                    string val = line.Substring(colon + 1).Trim();
                    if (string.Equals(key, "channel", StringComparison.OrdinalIgnoreCase) &&
                        int.TryParse(val, out int ch) && CH.Contains(ch))
                        currentCh = ch;
                    else if (string.Equals(key, "in use", StringComparison.OrdinalIgnoreCase) && currentCh > 0)
                        results[currentCh] = results.GetValueOrDefault(currentCh, 0) + (val.Equals("1") ? 1 : 0);
                }
                foreach (int ch in channels)
                {
                    if (!results.ContainsKey(ch))
                        results[ch] = 0;
                    if (Is2GhzChannel(ch))
                    {
                        int rssi = await MeasureRssi(interfaceName, ch).ConfigureAwait(false);
                        results[ch] = Math.Max(results[ch], (int)Math.Round(CalculateUtilization(0, rssi)));
                    }
                }
            }
            else
            {
                var rng = new Random();
                foreach (int ch in channels)
                    results[ch] = rng.Next(10, 90);
            }

            return results;
        }

        private static bool Is2GhzChannel(int channel) => channel >= 1 && channel <= 14;

        private static async Task<int> MeasureRssi(string interfaceName, int channel)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = "wlan show interfaces",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null) return -100;
                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                int sigIdx = output.IndexOf("Signal", StringComparison.OrdinalIgnoreCase);
                if (sigIdx >= 0)
                {
                    int pctIdx = output.IndexOf('%', sigIdx);
                    if (pctIdx < 0) return -100;
                    int start = output.LastIndexOf(':', sigIdx - 1) + 1;
                    if (pctIdx > start && int.TryParse(output.Substring(start, pctIdx - start).Trim(), out int pct))
                        return (int)Math.Round((pct / 100.0) * 60 - 100);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "iw",
                    Arguments = $"dev \"{interfaceName}\" link",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null) return -100;
                string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                await proc.WaitForExitAsync().ConfigureAwait(false);

                int sigIdx = output.IndexOf("signal:", StringComparison.OrdinalIgnoreCase);
                if (sigIdx >= 0)
                {
                    int end = output.IndexOf(' ', sigIdx + 7);
                    if (end < 0) end = output.Length;
                    string val = output.Substring(sigIdx + 7, end - sigIdx - 7).Trim();
                    if (int.TryParse(val, out int sig))
                        return sig;
                }
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
