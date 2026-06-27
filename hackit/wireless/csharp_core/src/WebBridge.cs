using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace HackITWireless
{
    public class WebBridge
    {
        private HttpListener? listener;
        private CancellationTokenSource? cts;
        private Task? serverTask;
        private readonly WifiScanner scanner;
        private readonly AttackEngine attackEngine;
        private readonly PacketCapture capture;

        public WebBridge()
        {
            scanner = new WifiScanner();
            attackEngine = new AttackEngine();
            capture = new PacketCapture();
        }

        public string StartServer(int port)
        {
            if (listener != null && listener.IsListening)
                return JsonSerializer.Serialize(new { error = "Server already running" });

            try
            {
                listener = new HttpListener();
                listener.Prefixes.Add($"http://*:{port}/");
                listener.Start();
                cts = new CancellationTokenSource();
                var token = cts.Token;

                serverTask = Task.Run(async () =>
                {
                    Console.Error.WriteLine($"[WEB] Server started on port {port}");
                    while (!token.IsCancellationRequested)
                    {
                        try
                        {
                            var ctx = await listener.GetContextAsync().ConfigureAwait(false);
                            await HandleRequest(ctx).ConfigureAwait(false);
                        }
                        catch (ObjectDisposedException) { break; }
                        catch (HttpListenerException) { break; }
                    }
                }, token);

                return JsonSerializer.Serialize(new { status = "started", port });
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }

        public string StopServer()
        {
            cts?.Cancel();
            try
            {
                listener?.Stop();
                listener?.Close();
            }
            catch { }
            listener = null;
            return JsonSerializer.Serialize(new { status = "stopped" });
        }

        private async Task HandleRequest(HttpListenerContext ctx)
        {
            try
            {
                var request = ctx.Request;
                var response = ctx.Response;
                string jsonResult;

                switch (request.Url?.AbsolutePath)
                {
                    case "/health":
                        jsonResult = JsonSerializer.Serialize(new
                        {
                            status = "ok",
                            timestamp = DateTime.UtcNow.ToString("O"),
                            version = "1.0.0"
                        });
                        break;

                    case "/scan":
                        jsonResult = scanner.ScanNetworks();
                        break;

                    case "/attack":
                        jsonResult = await HandleAttackRequest(request).ConfigureAwait(false);
                        break;

                    case "/status":
                        jsonResult = JsonSerializer.Serialize(new
                        {
                            capturing = capture.IsCapturing,
                            server_running = listener?.IsListening ?? false
                        });
                        break;

                    default:
                        response.StatusCode = 404;
                        jsonResult = JsonSerializer.Serialize(new { error = "Not found" });
                        break;
                }

                byte[] buffer = Encoding.UTF8.GetBytes(jsonResult);
                response.ContentType = "application/json";
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.OutputStream.Close();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[WEB] Request error: {ex.Message}");
            }
        }

        private async Task<string> HandleAttackRequest(HttpListenerRequest request)
        {
            try
            {
                string body;
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    body = await reader.ReadToEndAsync().ConfigureAwait(false);
                }

                var data = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(body);
                if (data == null)
                    return JsonSerializer.Serialize(new { error = "Invalid JSON" });

                string type = data.GetValueOrDefault("type", default).GetString() ?? "";
                string iface = data.GetValueOrDefault("interface", default).GetString() ?? DetectInterface();
                string bssid = data.GetValueOrDefault("bssid", default).GetString() ?? "FF:FF:FF:FF:FF:FF";
                string station = data.GetValueOrDefault("station", default).GetString() ?? "";
                int count = data.GetValueOrDefault("count", default).GetInt32();
                int timeout = data.GetValueOrDefault("timeout", default).GetInt32();

                return type switch
                {
                    "deauth" => await attackEngine.DeauthAttack(bssid, station, 0, iface),
                    "beacon" => await attackEngine.BeaconFlood(
                        data.GetValueOrDefault("ssid", default).GetString() ?? $"AP_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 10000}",
                        count > 0 ? count : 50, iface),
                    "handshake" => await attackEngine.HandshakeCapture(bssid, timeout > 0 ? timeout : 30, iface,
                        data.GetValueOrDefault("output", default).GetString() ?? "capture.pcap"),
                    "wps" => await attackEngine.WpsAttack(bssid, iface,
                        data.GetValueOrDefault("method", default).GetString() ?? ""),
                    _ => JsonSerializer.Serialize(new { error = $"Unknown attack type: {type}" })
                };
            }
            catch (Exception ex)
            {
                return JsonSerializer.Serialize(new { error = ex.Message });
            }
        }
    }
}
