using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace HackITWireless
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Error.WriteLine("HackIT Wireless C# Core");
                Console.Error.WriteLine("Usage:");
                Console.Error.WriteLine("  scan [interface]");
                Console.Error.WriteLine("  deauth <bssid> <station> <count> <interface>");
                Console.Error.WriteLine("  beacon <ssid> <count> <interface>");
                Console.Error.WriteLine("  handshake <bssid> <timeout> <interface> [output]");
                Console.Error.WriteLine("  wps <bssid> <interface> [method]");
                Console.Error.WriteLine("  capture <interface> [filter]");
                Console.Error.WriteLine("  server <port>");
                return 1;
            }

            try
            {
                return args[0] switch
                {
                    "scan" => await RunScan(args),
                    "deauth" => await RunDeauth(args),
                    "beacon" => await RunBeacon(args),
                    "handshake" => await RunHandshake(args),
                    "wps" => await RunWps(args),
                    "capture" => await RunCapture(args),
                    "server" => RunServer(args),
                    _ => RunHelp()
                };
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        static async Task<int> RunScan(string[] args)
        {
            var scanner = new WifiScanner();
            string result = scanner.ScanNetworks();
            Console.WriteLine(result);
            return 0;
        }

        static async Task<int> RunDeauth(string[] args)
        {
            if (args.Length < 3) { Console.Error.WriteLine("Usage: deauth <bssid> <station> <count> [interface]"); return 1; }
            var engine = new AttackEngine();
            string bssid = args[1], station = args[2];
            int count = int.Parse(args[3]);
            string iface = args.Length > 4 ? args[4] : DetectInterface();
            Console.WriteLine(await engine.DeauthAttack(bssid, station, count, iface));
            return 0;
        }

        static async Task<int> RunBeacon(string[] args)
        {
            if (args.Length < 2) { Console.Error.WriteLine("Usage: beacon <ssid> <count> [interface]"); return 1; }
            var engine = new AttackEngine();
            string ssid = args[1];
            int count = int.Parse(args[2]);
            string iface = args.Length > 3 ? args[3] : DetectInterface();
            Console.WriteLine(await engine.BeaconFlood(ssid, count, iface));
            return 0;
        }

        static async Task<int> RunHandshake(string[] args)
        {
            if (args.Length < 2) { Console.Error.WriteLine("Usage: handshake <bssid> <timeout> [interface] [output]"); return 1; }
            var engine = new AttackEngine();
            string bssid = args[1];
            int timeout = int.Parse(args[2]);
            string iface = args.Length > 3 ? args[3] : DetectInterface();
            string output = args.Length > 4 ? args[4] : "capture.pcap";
            Console.WriteLine(await engine.HandshakeCapture(bssid, timeout, iface, output));
            return 0;
        }

        static async Task<int> RunWps(string[] args)
        {
            if (args.Length < 1) { Console.Error.WriteLine("Usage: wps <bssid> [interface] [method]"); return 1; }
            var engine = new AttackEngine();
            string bssid = args[1];
            string iface = args.Length > 2 ? args[2] : DetectInterface();
            string method = args.Length > 3 ? args[3] : "pixie";
            Console.WriteLine(await engine.WpsAttack(bssid, iface, method));
            return 0;
        }

        static async Task<int> RunCapture(string[] args)
        {
            string iface = args.Length > 1 ? args[1] : DetectInterface();
            string filter = args.Length > 2 ? args[2] : "";
            var capture = new PacketCapture();
            Console.WriteLine(capture.StartCapture(iface, filter));
            await Task.Delay(10000);
            Console.WriteLine(capture.StopCapture());
            Console.WriteLine(capture.GetCapturedFrames());
            return 0;
        }

        static string DetectInterface()
        {
            try
            {
                var proc = new System.Diagnostics.Process();
                proc.StartInfo.FileName = "iw";
                proc.StartInfo.Arguments = "dev";
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.Start();
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                foreach (var line in output.Split('\n'))
                {
                    if (line.Contains("Interface"))
                    {
                        var parts = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 0) return parts[parts.Length - 1];
                    }
                }
            }
            catch { }
            return "";
        }

        static int RunServer(string[] args)
        {
            int port = args.Length > 1 ? int.Parse(args[1]) : 8080;
            var bridge = new WebBridge();
            Console.WriteLine(bridge.StartServer(port));
            Console.Error.WriteLine($"Server running on port {port}. Press Ctrl+C to stop.");
            System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite);
            return 0;
        }

        static int RunHelp()
        {
            Console.Error.WriteLine("Unknown command. Use no arguments for help.");
            return 1;
        }
    }
}
