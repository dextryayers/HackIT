using System;
using System.Collections.Concurrent;
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
    public class PacketCapture
    {
        private CancellationTokenSource? cts;
        private Task? captureTask;
        private readonly ConcurrentQueue<Dictionary<string, object>> frameQueue = new();
        private volatile bool isCapturing;

        public string StartCapture(string iface, string? filter = null)
        {
            if (isCapturing)
                return JsonSerializer.Serialize(new { error = "Already capturing" });

            cts = new CancellationTokenSource();
            isCapturing = true;
            var token = cts.Token;

            captureTask = Task.Run(async () =>
            {
                try
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        string filterArg = string.IsNullOrEmpty(filter) ? "" : $" \"{filter}\"";
                        var psi = new ProcessStartInfo
                        {
                            FileName = "tcpdump",
                            Arguments = $"-i {iface} -x -s 0{filterArg} 2>/dev/null",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true
                        };

                        using var proc = Process.Start(psi);
                        if (proc == null) return;

                        var reader = new StreamReader(proc.StandardOutput.BaseStream);
                        var lineBuf = new StringBuilder();

                        while (!token.IsCancellationRequested && !reader.EndOfStream)
                        {
                            char[] buf = new char[4096];
                            int read = await reader.ReadAsync(buf, 0, buf.Length);
                            if (read == 0) break;

                            for (int i = 0; i < read; i++)
                            {
                                if (buf[i] == '\n')
                                {
                                    string line = lineBuf.ToString().Trim();
                                    lineBuf.Clear();
                                    if (line.Length > 0)
                                    {
                                        var frame = new Dictionary<string, object>
                                        {
                                            ["timestamp"] = DateTime.Now.ToString("O"),
                                            ["data"] = line,
                                            ["length"] = line.Length
                                        };
                                        frameQueue.Enqueue(frame);
                                    }
                                }
                                else
                                {
                                    lineBuf.Append(buf[i]);
                                }
                            }

                            if (frameQueue.Count > 1000)
                            {
                                while (frameQueue.Count > 500)
                                {
                                    frameQueue.TryDequeue(out _);
                                }
                            }
                        }

                        try { proc.Kill(); } catch { }
                    }
                    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        await Task.Delay(1000, token);
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[PCAP] Capture error: {ex.Message}");
                }
                finally
                {
                    isCapturing = false;
                }
            }, token);

            return JsonSerializer.Serialize(new { status = "capturing", interface_name = iface, filter = filter });
        }

        public string StopCapture()
        {
            if (!isCapturing)
                return JsonSerializer.Serialize(new { error = "Not capturing" });

            cts?.Cancel();
            try
            {
                captureTask?.Wait(TimeSpan.FromSeconds(3));
            }
            catch { }

            int count = frameQueue.Count;
            isCapturing = false;
            return JsonSerializer.Serialize(new { status = "stopped", frames_captured = count });
        }

        public string GetCapturedFrames(int maxFrames = 100)
        {
            var frames = new List<Dictionary<string, object>>();
            while (frames.Count < maxFrames && frameQueue.TryDequeue(out var frame))
            {
                frames.Add(frame);
            }

            var result = new Dictionary<string, object>
            {
                ["count"] = frames.Count,
                ["frames"] = frames
            };
            return JsonSerializer.Serialize(result);
        }

        public bool IsCapturing => isCapturing;
    }
}
