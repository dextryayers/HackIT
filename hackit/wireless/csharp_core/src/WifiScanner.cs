using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace HackITWireless
{
    public class WifiScanner
    {
        private const int WLAN_API_VERSION_2_0 = 2;
        private IntPtr clientHandle = IntPtr.Zero;
        private int negotiatedVersion;

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanOpenHandle(
            int clientVersion, IntPtr reserved,
            out int negotiatedVersion, out IntPtr clientHandle);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanCloseHandle(
            IntPtr clientHandle, IntPtr reserved);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanScan(
            IntPtr clientHandle, ref Guid interfaceGuid,
            IntPtr dot11Ssid, IntPtr ies, IntPtr reserved);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanGetAvailableNetworkList(
            IntPtr clientHandle, ref Guid interfaceGuid,
            int flags, IntPtr reserved,
            out IntPtr availableNetworkList);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern void WlanFreeMemory(IntPtr ptr);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern int WlanEnumInterfaces(
            IntPtr clientHandle, IntPtr reserved,
            out IntPtr interfaceList);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WLAN_INTERFACE_INFO
        {
            public Guid interfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;
            public uint isState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_INTERFACE_INFO_LIST
        {
            public int numberOfItems;
            public int index;
            public WLAN_INTERFACE_INFO[] interfaceInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_AVAILABLE_NETWORK
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string profileName;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)]
            public string dot11Ssid;
            public uint dot11BssType;
            public uint numberOfBssids;
            public bool networkConnectable;
            public uint wlanNotConnectableReason;
            public uint numberOfPhyTypes;
            public uint signalQuality;
            public int securityEnabled;
            public uint dot11DefaultAuthAlgorithm;
            public uint dot11DefaultCipherAlgorithm;
            public uint flagsEx;
            public uint dot11Rssi;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_AVAILABLE_NETWORK_LIST
        {
            public int numberOfItems;
            public int index;
            public IntPtr networkPtr;
        }

        public WifiScanner()
        {
            int ret = WlanOpenHandle(WLAN_API_VERSION_2_0, IntPtr.Zero,
                out negotiatedVersion, out clientHandle);
            if (ret != 0)
                Console.Error.WriteLine($"WlanOpenHandle failed: {ret}");
        }

        public string ScanNetworks()
        {
            if (clientHandle == IntPtr.Zero)
                return "{\"error\":\"No WLAN handle\"}";

            var results = new List<Dictionary<string, object>>();
            try
            {
                IntPtr ifListPtr;
                int ret = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out ifListPtr);
                if (ret != 0)
                    return "{\"error\":\"WlanEnumInterfaces failed\"}";

                var result = new List<Dictionary<string, object>>();
                WlanFreeMemory(ifListPtr);
                result.Add(new Dictionary<string, object>
                {
                    ["ssid"] = "MockNetwork",
                    ["bssid"] = "00:11:22:33:44:55",
                    ["signal"] = 85,
                    ["channel"] = 6,
                    ["security"] = "WPA2",
                    ["hidden"] = false
                });
                return JsonSerializer.Serialize(result);
            }
            catch (Exception ex)
            {
                return $"{{\"error\":\"{ex.Message}\"}}";
            }
        }

        public string GetHiddenSSIDs()
        {
            var hidden = new List<Dictionary<string, object>>();
            hidden.Add(new Dictionary<string, object>
            {
                ["bssid"] = "AA:BB:CC:DD:EE:FF",
                ["signal"] = 72,
                ["channel"] = 11
            });
            return JsonSerializer.Serialize(hidden);
        }

        public void Close()
        {
            if (clientHandle != IntPtr.Zero)
            {
                WlanCloseHandle(clientHandle, IntPtr.Zero);
                clientHandle = IntPtr.Zero;
            }
        }
    }
}
