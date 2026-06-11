using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace HackItWireless
{
    public enum Band
    {
        Band2_4GHz,
        Band5GHz,
        BandBoth
    }

    public readonly struct ChannelInfo
    {
        public int Channel { get; }
        public double FrequencyMhz { get; }
        public Band Band { get; }

        public ChannelInfo(int channel, double frequencyMhz, Band band)
        {
            Channel = channel;
            FrequencyMhz = frequencyMhz;
            Band = band;
        }

        public override string ToString() =>
            $"Ch {Channel} @ {FrequencyMhz} MHz ({Band})";
    }

    public sealed class ChannelManager : IDisposable
    {
        private readonly string _interfaceName;
        private readonly Band _supportedBand;
        private int _currentChannel;
        private bool _hopping;
        private CancellationTokenSource? _hopCts;
        private static readonly Random Rng = new();

        private static readonly Dictionary<int, ChannelInfo> ChannelMap2Ghz = new()
        {
            { 1,  new ChannelInfo(1,  2412, Band.Band2_4GHz) },
            { 2,  new ChannelInfo(2,  2417, Band.Band2_4GHz) },
            { 3,  new ChannelInfo(3,  2422, Band.Band2_4GHz) },
            { 4,  new ChannelInfo(4,  2427, Band.Band2_4GHz) },
            { 5,  new ChannelInfo(5,  2432, Band.Band2_4GHz) },
            { 6,  new ChannelInfo(6,  2437, Band.Band2_4GHz) },
            { 7,  new ChannelInfo(7,  2442, Band.Band2_4GHz) },
            { 8,  new ChannelInfo(8,  2447, Band.Band2_4GHz) },
            { 9,  new ChannelInfo(9,  2452, Band.Band2_4GHz) },
            { 10, new ChannelInfo(10, 2457, Band.Band2_4GHz) },
            { 11, new ChannelInfo(11, 2462, Band.Band2_4GHz) },
            { 12, new ChannelInfo(12, 2467, Band.Band2_4GHz) },
            { 13, new ChannelInfo(13, 2472, Band.Band2_4GHz) },
            { 14, new ChannelInfo(14, 2484, Band.Band2_4GHz) },
        };

        private static readonly Dictionary<int, ChannelInfo> ChannelMap5Ghz = new()
        {
            { 36,  new ChannelInfo(36,  5180, Band.Band5GHz) },
            { 40,  new ChannelInfo(40,  5200, Band.Band5GHz) },
            { 44,  new ChannelInfo(44,  5220, Band.Band5GHz) },
            { 48,  new ChannelInfo(48,  5240, Band.Band5GHz) },
            { 52,  new ChannelInfo(52,  5260, Band.Band5GHz) },
            { 56,  new ChannelInfo(56,  5280, Band.Band5GHz) },
            { 60,  new ChannelInfo(60,  5300, Band.Band5GHz) },
            { 64,  new ChannelInfo(64,  5320, Band.Band5GHz) },
            { 100, new ChannelInfo(100, 5500, Band.Band5GHz) },
            { 104, new ChannelInfo(104, 5520, Band.Band5GHz) },
            { 108, new ChannelInfo(108, 5540, Band.Band5GHz) },
            { 112, new ChannelInfo(112, 5560, Band.Band5GHz) },
            { 116, new ChannelInfo(116, 5580, Band.Band5GHz) },
            { 120, new ChannelInfo(120, 5600, Band.Band5GHz) },
            { 124, new ChannelInfo(124, 5620, Band.Band5GHz) },
            { 128, new ChannelInfo(128, 5640, Band.Band5GHz) },
            { 132, new ChannelInfo(132, 5660, Band.Band5GHz) },
            { 136, new ChannelInfo(136, 5680, Band.Band5GHz) },
            { 140, new ChannelInfo(140, 5700, Band.Band5GHz) },
            { 144, new ChannelInfo(144, 5720, Band.Band5GHz) },
            { 149, new ChannelInfo(149, 5745, Band.Band5GHz) },
            { 153, new ChannelInfo(153, 5765, Band.Band5GHz) },
            { 157, new ChannelInfo(157, 5785, Band.Band5GHz) },
            { 161, new ChannelInfo(161, 5805, Band.Band5GHz) },
            { 165, new ChannelInfo(165, 5825, Band.Band5GHz) },
        };

        public string InterfaceName => _interfaceName;
        public int CurrentChannel => _currentChannel;
        public bool IsHopping => _hopping;

        public ChannelManager(string interfaceName, Band band = Band.BandBoth)
        {
            if (string.IsNullOrWhiteSpace(interfaceName))
                throw new ArgumentException("Interface name cannot be null or empty.", nameof(interfaceName));

            _interfaceName = interfaceName.Trim();
            _supportedBand = band;
            _currentChannel = 0;
        }

        public IReadOnlyList<ChannelInfo> GetAvailableChannels()
        {
            var channels = new List<ChannelInfo>();

            if (_supportedBand == Band.Band2_4GHz || _supportedBand == Band.BandBoth)
                channels.AddRange(ChannelMap2Ghz.Values);

            if (_supportedBand == Band.Band5GHz || _supportedBand == Band.BandBoth)
                channels.AddRange(ChannelMap5Ghz.Values);

            return channels.AsReadOnly();
        }

        public ChannelInfo? GetChannelInfo(int channel)
        {
            if (ChannelMap2Ghz.TryGetValue(channel, out var info2))
                return info2;
            if (ChannelMap5Ghz.TryGetValue(channel, out var info5))
                return info5;
            return null;
        }

        public double GetChannelFrequency(int channel)
        {
            var info = GetChannelInfo(channel);
            if (info == null)
                throw new ArgumentOutOfRangeException(nameof(channel),
                    $"Channel {channel} is not a valid 2.4GHz or 5GHz channel.");

            return info.Value.FrequencyMhz;
        }

        public bool SetChannel(int channel)
        {
            var info = GetChannelInfo(channel);
            if (info == null)
                throw new ArgumentOutOfRangeException(nameof(channel),
                    $"Channel {channel} is not supported. Use channels 1-14 (2.4GHz) or 36-165 (5GHz).");

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    SetChannelWindows(channel);
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    SetChannelLinux(channel);
                else
                    throw new PlatformNotSupportedException(
                        "Channel setting is only supported on Windows and Linux.");

                _currentChannel = channel;
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Failed to set channel {channel} on interface '{_interfaceName}': {ex.Message}", ex);
            }
        }

        public async Task HopChannels(
            IEnumerable<int>? channels = null,
            int dwellTimeMs = 300,
            bool randomizeOrder = false,
            CancellationToken? cancellationToken = null)
        {
            if (_hopping)
                throw new InvalidOperationException("Channel hopping is already in progress. Stop it first.");

            var channelList = channels != null
                ? new List<int>(channels)
                : GetAvailableChannels().Select(c => c.Channel).ToList();

            if (channelList.Count == 0)
                throw new ArgumentException("No channels to hop on.", nameof(channels));

            foreach (var ch in channelList)
            {
                var info = GetChannelInfo(ch);
                if (info == null)
                    throw new ArgumentOutOfRangeException(nameof(channels),
                        $"Channel {ch} is not a valid channel.");
            }

            _hopping = true;
            _hopCts = cancellationToken ?? new CancellationTokenSource();

            try
            {
                var orderedChannels = randomizeOrder
                    ? ShuffleList(channelList)
                    : channelList;

                while (!_hopCts.Token.IsCancellationRequested)
                {
                    foreach (var ch in orderedChannels)
                    {
                        if (_hopCts.Token.IsCancellationRequested)
                            break;

                        SetChannel(ch);
                        await Task.Delay(dwellTimeMs, _hopCts.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal stop
            }
            finally
            {
                _hopping = false;
                if (cancellationToken == null)
                    _hopCts?.Dispose();
                _hopCts = null;
            }
        }

        public void StopHopping()
        {
            if (_hopCts != null && !_hopCts.IsCancellationRequested)
                _hopCts.Cancel();
        }

        public async Task<Dictionary<int, List<string>>> ScanAllChannels(
            int dwellTimeMs = 500,
            string? airodumpPath = null,
            CancellationToken? cancellationToken = null)
        {
            var results = new Dictionary<int, List<string>>();
            var channelList = GetAvailableChannels();
            var cts = cancellationToken ?? new CancellationTokenSource();

            string airodump = airodumpPath ?? (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? "airodump-ng"
                : "airodump-ng");

            string tempDir = Path.Combine(Path.GetTempPath(), $"hackit_scan_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);

            try
            {
                foreach (var channelInfo in channelList)
                {
                    if (cts.Token.IsCancellationRequested)
                        break;

                    SetChannel(channelInfo.Channel);

                    string prefix = Path.Combine(tempDir, $"ch{channelInfo.Channel}");

                    var psi = new ProcessStartInfo
                    {
                        FileName = airodump,
                        Arguments = $"--channel {channelInfo.Channel} --write-interval 1 --output-format csv " +
                                    $"--write \"{prefix}\" \"{_interfaceName}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    };

                    using var proc = Process.Start(psi);
                    if (proc == null)
                    {
                        results[channelInfo.Channel] = new List<string> { "<process failed to start>" };
                        continue;
                    }

                    await Task.Delay(dwellTimeMs, cts.Token).ConfigureAwait(false);

                    try
                    {
                        proc.Kill();
                    }
                    catch
                    {
                        // Process may have already exited
                    }

                    string csvFile = prefix + "-01.csv";
                    var aps = ParseAirodumpCsv(csvFile);
                    results[channelInfo.Channel] = aps;

                    if (File.Exists(csvFile))
                    {
                        try { File.Delete(csvFile); } catch { /* best effort */ }
                    }
                }
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempDir))
                        Directory.Delete(tempDir, true);
                }
                catch { /* best effort cleanup */ }
            }

            return results;
        }

        private static List<string> ParseAirodumpCsv(string csvPath)
        {
            var aps = new List<string>();
            if (!File.Exists(csvPath))
                return aps;

            try
            {
                string[] lines = File.ReadAllLines(csvPath);
                bool inApSection = false;

                foreach (var line in lines)
                {
                    string trimmed = line.Trim();

                    if (string.IsNullOrEmpty(trimmed))
                    {
                        inApSection = false;
                        continue;
                    }

                    if (trimmed.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                    {
                        inApSection = true;
                        continue;
                    }

                    if (inApSection && !trimmed.StartsWith("Station", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] fields = trimmed.Split(',');
                        if (fields.Length >= 14)
                        {
                            string bssid = fields[0].Trim();
                            string power = fields[8].Trim();
                            string ch = fields[3].Trim();
                            string essid = fields[13].Trim();

                            if (!string.IsNullOrEmpty(bssid) && bssid != "(not associated)")
                            {
                                aps.Add($"{bssid} | Ch {ch} | Pwr {power} | {essid}");
                            }
                        }
                    }
                }
            }
            catch
            {
                aps.Add("<error parsing CSV>");
            }

            return aps;
        }

        public static async Task<string> DetectInterface()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return await DetectInterfaceWindows().ConfigureAwait(false);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return await DetectInterfaceLinux().ConfigureAwait(false);

            throw new PlatformNotSupportedException("Interface detection only supported on Windows and Linux.");
        }

        private static async Task<string> DetectInterfaceWindows()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "wlan show interfaces",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                throw new InvalidOperationException("Failed to start netsh process.");

            string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            await proc.WaitForExitAsync().ConfigureAwait(false);

            var match = Regex.Match(output, @"Name\s*:\s*(.+)", RegexOptions.IgnoreCase);
            if (match.Success)
                return match.Groups[1].Value.Trim();

            throw new InvalidOperationException("No wireless interface detected on Windows.");
        }

        private static async Task<string> DetectInterfaceLinux()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "iw",
                Arguments = "dev",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                throw new InvalidOperationException("Failed to start iw process.");

            string output = await proc.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            await proc.WaitForExitAsync().ConfigureAwait(false);

            var match = Regex.Match(output, @"Interface\s+(\S+)");
            if (match.Success)
                return match.Groups[1].Value;

            throw new InvalidOperationException("No wireless interface detected on Linux.");
        }

        private static void SetChannelWindows(int channel)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"wlan set network mode mode=bssid interface=\"*\" " +
                            $"band={GetWindowsBand(channel)} channel={channel}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                throw new InvalidOperationException("Failed to start netsh for channel setting.");

            proc.WaitForExit(5000);

            if (proc.ExitCode != 0)
            {
                string stderr = proc.StandardError.ReadToEnd();
                throw new InvalidOperationException(
                    $"netsh exited with code {proc.ExitCode}: {stderr}");
            }
        }

        private static string GetWindowsBand(int channel)
        {
            if (channel >= 1 && channel <= 14)
                return "2.4GHz";
            if (channel >= 36 && channel <= 165)
                return "5GHz";
            return "auto";
        }

        private static void SetChannelLinux(int channel)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "iw",
                Arguments = $"dev set channel {channel}",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                throw new InvalidOperationException("Failed to start iw for channel setting.");

            proc.WaitForExit(5000);

            if (proc.ExitCode != 0)
            {
                string stderr = proc.StandardError.ReadToEnd();
                throw new InvalidOperationException(
                    $"iw exited with code {proc.ExitCode}: {stderr}");
            }
        }

        private static List<T> ShuffleList<T>(List<T> list)
        {
            var shuffled = new List<T>(list);
            int n = shuffled.Count;
            while (n > 1)
            {
                n--;
                int k = Rng.Next(n + 1);
                (shuffled[k], shuffled[n]) = (shuffled[n], shuffled[k]);
            }
            return shuffled;
        }

        public void Dispose()
        {
            StopHopping();
            _hopCts?.Dispose();
        }
    }
}
