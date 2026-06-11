using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HackItWireless
{
    public enum EapolKeyInfo : ushort
    {
        Pairwise = 0x0008,
        Group = 0x0004,
        Install = 0x0040,
        Ack = 0x0080,
        Mic = 0x0100,
        Secure = 0x0200,
        Error = 0x0400,
        Request = 0x0800,
    }

    public readonly struct EapolFrame
    {
        public byte Version { get; }
        public byte Type { get; }
        public ushort Length { get; }
        public ushort KeyDescriptorType { get; }
        public ushort KeyInfo { get; }
        public uint KeyLength { get; }
        public byte[] ReplayCounter { get; }
        public byte[] Nonce { get; }
        public byte[] KeyIv { get; }
        public byte[] KeyRsc { get; }
        public byte[] KeyId { get; }
        public byte[] KeyMic { get; }
        public ushort KeyDataLength { get; }
        public byte[] KeyData { get; }

        public EapolFrame(
            byte version, byte type, ushort length,
            ushort keyDescriptorType, ushort keyInfo, uint keyLength,
            byte[] replayCounter, byte[] nonce, byte[] keyIv,
            byte[] keyRsc, byte[] keyId, byte[] keyMic,
            ushort keyDataLength, byte[] keyData)
        {
            Version = version;
            Type = type;
            Length = length;
            KeyDescriptorType = keyDescriptorType;
            KeyInfo = keyInfo;
            KeyLength = keyLength;
            ReplayCounter = replayCounter;
            Nonce = nonce;
            KeyIv = keyIv;
            KeyRsc = keyRsc;
            KeyId = keyId;
            KeyMic = keyMic;
            KeyDataLength = keyDataLength;
            KeyData = keyData;
        }

        public bool HasFlag(EapolKeyInfo flag) => (KeyInfo & (ushort)flag) != 0;

        public int MessageNumber
        {
            get
            {
                bool ack = HasFlag(EapolKeyInfo.Ack);
                bool mic = HasFlag(EapolKeyInfo.Mic);
                bool install = HasFlag(EapolKeyInfo.Install);

                if (ack && !mic) return 1;
                if (!ack && !mic && !install) return 2;
                if (!ack && mic && install) return 3;
                if (!ack && mic && !install) return 4;
                return 0;
            }
        }
    }

    public readonly struct HandshakeResult
    {
        public bool IsValid { get; }
        public string? Message { get; }
        public string? SourceMac { get; }
        public string? DestinationMac { get; }
        public string? AccessPointMac { get; }
        public byte[]? Pmkid { get; }
        public List<EapolFrame> EapolFrames { get; }
        public int CompleteMessages { get; }

        public HandshakeResult(
            bool isValid, string? message, string? sourceMac,
            string? destinationMac, string? accessPointMac,
            byte[]? pmkid, List<EapolFrame> eapolFrames, int completeMessages)
        {
            IsValid = isValid;
            Message = message;
            SourceMac = sourceMac;
            DestinationMac = destinationMac;
            AccessPointMac = accessPointMac;
            Pmkid = pmkid;
            EapolFrames = eapolFrames;
            CompleteMessages = completeMessages;
        }
    }

    public sealed class HandshakeCapture
    {
        private readonly Dictionary<string, HandshakeResult> _capturedHandshakes = new();

        public IReadOnlyDictionary<string, HandshakeResult> CapturedHandshakes => _capturedHandshakes;

        public HandshakeResult CaptureHandshake(string pcapFilePath)
        {
            if (string.IsNullOrWhiteSpace(pcapFilePath))
                throw new ArgumentException("PCAP file path cannot be null or empty.", nameof(pcapFilePath));

            if (!File.Exists(pcapFilePath))
                throw new FileNotFoundException($"PCAP file not found: {pcapFilePath}", pcapFilePath);

            byte[] fileBytes = File.ReadAllBytes(pcapFilePath);

            if (fileBytes.Length < 24)
                throw new InvalidDataException("File is too small to be a valid PCAP file.");

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(0, 4));
            bool isSwapped = false;

            if (magic == 0xA1B2C3D4)
                isSwapped = false;
            else if (magic == 0xD4C3B2A1)
                isSwapped = true;
            else
                throw new InvalidDataException(
                    $"Invalid PCAP magic number: 0x{magic:X8}. Expected 0xA1B2C3D4 or 0xD4C3B2A1.");

            var packets = ParsePcapFile(fileBytes, isSwapped);
            var eapolFrames = new List<EapolFrame>();
            string? srcMac = null;
            string? dstMac = null;
            string? bssid = null;

            foreach (var packet in packets)
            {
                if (packet.Data.Length < 14)
                    continue;

                ushort ethType = isSwapped
                    ? BinaryPrimitives.ReadUInt16BigEndian(packet.Data.AsSpan(12, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(packet.Data.AsSpan(12, 2));

                int ipOffset = 14;

                if (ethType == 0x8100)
                {
                    ipOffset += 4;
                    ethType = isSwapped
                        ? BinaryPrimitives.ReadUInt16BigEndian(packet.Data.AsSpan(16, 2))
                        : BinaryPrimitives.ReadUInt16LittleEndian(packet.Data.AsSpan(16, 2));
                }

                if (ethType == 0x0800 && packet.Data.Length >= ipOffset + 20)
                {
                    byte ipProto = packet.Data[ipOffset + 9];
                    if (ipProto == 0x11)
                    {
                        int udpOffset = ipOffset + 20;
                        if (packet.Data.Length >= udpOffset + 8)
                        {
                            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(
                                packet.Data.AsSpan(udpOffset, 2));
                            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(
                                packet.Data.AsSpan(udpOffset + 2, 2));

                            if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68)
                            {
                                int dhcpOffset = udpOffset + 8;
                                if (packet.Data.Length >= dhcpOffset + 1)
                                {
                                    bssid = ExtractBssidFromDhcp(packet.Data, dhcpOffset);
                                }
                            }
                        }
                    }
                }

                if (ethType == 0x0806)
                {
                    if (packet.Data.Length >= 42)
                    {
                        srcMac = FormatMac(packet.Data, 22);
                        dstMac = FormatMac(packet.Data, 32);
                        bssid ??= FormatMac(packet.Data, 22);
                    }
                }

                if (ethType != 0x888E)
                    continue;

                if (packet.Data.Length >= 26)
                {
                    srcMac = FormatMac(packet.Data, 6);
                    dstMac = FormatMac(packet.Data, 0);
                }

                var eapol = ParseEapolFrame(packet.Data, 14, isSwapped);
                if (eapol != null)
                {
                    eapolFrames.Add(eapol.Value);
                    bssid ??= srcMac;
                }
            }

            var messages = eapolFrames
                .Where(f => f.MessageNumber > 0)
                .GroupBy(f => f.MessageNumber)
                .Select(g => g.First())
                .OrderBy(f => f.MessageNumber)
                .ToList();

            bool isValid = messages.Count >= 3;
            string message = isValid
                ? $"Handshake captured with {messages.Count} complete messages."
                : $"Incomplete handshake: {messages.Count}/4 EAPOL messages found.";

            byte[]? pmkid = ExtractPmkid(eapolFrames);

            if (pmkid != null)
            {
                isValid = true;
                message = $"PMKID captured from EAPOL frames. {messages.Count}/4 messages present.";
            }

            string? accessPoint = bssid ?? srcMac;

            var result = new HandshakeResult(
                isValid,
                message,
                srcMac,
                dstMac,
                accessPoint,
                pmkid,
                eapolFrames,
                messages.Count);

            if (accessPoint != null)
                _capturedHandshakes[accessPoint] = result;

            return result;
        }

        public bool VerifyHandshake(HandshakeResult handshake)
        {
            if (!handshake.IsValid)
                return false;

            if (handshake.Pmkid != null && handshake.Pmkid.Length == 16)
                return true;

            var messages = handshake.EapolFrames
                .Where(f => f.MessageNumber > 0)
                .GroupBy(f => f.MessageNumber)
                .Select(g => g.First())
                .OrderBy(f => f.MessageNumber)
                .ToList();

            if (messages.Count < 3)
                return false;

            bool hasMsg1 = messages.Any(f => f.MessageNumber == 1);
            bool hasMsg2 = messages.Any(f => f.MessageNumber == 2);
            bool hasMsg3 = messages.Any(f => f.MessageNumber == 3);
            bool hasMsg4 = messages.Any(f => f.MessageNumber == 4);

            if (hasMsg1 && hasMsg2 && hasMsg3 && hasMsg4)
                return true;

            if (hasMsg1 && hasMsg2 && hasMsg3)
                return true;

            if (hasMsg2 && hasMsg3 && hasMsg4)
                return true;

            if (hasMsg1 && hasMsg2 && hasMsg4)
                return true;

            return false;
        }

        public byte[]? ExtractPmkid(List<EapolFrame> eapolFrames)
        {
            foreach (var frame in eapolFrames)
            {
                if (frame.KeyData == null || frame.KeyDataLength < 39)
                    continue;

                int offset = 0;
                while (offset + 2 < frame.KeyDataLength)
                {
                    byte elemId = frame.KeyData[offset];
                    byte elemLen = frame.KeyData[offset + 1];

                    if (elemId == 0xDD && elemLen >= 20 && offset + 2 + elemLen <= frame.KeyDataLength)
                    {
                        byte[] oui = new byte[3];
                        Array.Copy(frame.KeyData, offset + 2, oui, 0, 3);

                        if (oui[0] == 0x00 && oui[1] == 0x0F && oui[2] == 0xAC)
                        {
                            byte type = frame.KeyData[offset + 5];
                            if (type == 0x04)
                            {
                                byte[] pmkid = new byte[16];
                                Array.Copy(frame.KeyData, offset + 6, pmkid, 0, 16);
                                return pmkid;
                            }
                        }
                    }

                    if (elemLen == 0)
                        break;
                    offset += 2 + elemLen;
                }
            }

            return null;
        }

        public string ConvertToHC22000(HandshakeResult handshake, string ssid)
        {
            if (handshake == null)
                throw new ArgumentNullException(nameof(handshake));
            if (string.IsNullOrWhiteSpace(ssid))
                throw new ArgumentException("SSID cannot be null or empty.", nameof(ssid));
            if (string.IsNullOrWhiteSpace(handshake.AccessPointMac))
                throw new InvalidOperationException("Access point MAC is not available.");

            string bssidClean = handshake.AccessPointMac.Replace(":", "").Replace("-", "").ToUpperInvariant();

            if (handshake.Pmkid != null)
            {
                string pmkidHex = Convert.ToHexString(handshake.Pmkid).ToLowerInvariant();
                return $"WPA*01*{pmkidHex}*{bssidHex(ssid)}*{bssidClean}*";
            }

            var messages = handshake.EapolFrames
                .Where(f => f.MessageNumber > 0)
                .GroupBy(f => f.MessageNumber)
                .Select(g => g.First())
                .OrderBy(f => f.MessageNumber)
                .ToList();

            if (messages.Count < 3)
                throw new InvalidOperationException(
                    "Insufficient EAPOL messages for HC22000 conversion. Need at least 3.");

            byte[]? anonce = null;
            byte[]? snonce = null;
            byte[]? mic = null;
            byte[]? eapolData = null;
            int keyDataLen = 0;

            foreach (var msg in messages)
            {
                if (msg.MessageNumber == 1)
                    anonce = msg.Nonce;
                else if (msg.MessageNumber == 2)
                    snonce = msg.Nonce;
            }

            var lastMsg = messages.Last();
            mic = lastMsg.KeyMic;

            if (mic == null || mic.Length == 0)
                throw new InvalidOperationException("No MIC found in captured messages.");

            anonce ??= messages[0].Nonce;
            snonce ??= messages.Count > 1 ? messages[1].Nonce : messages[0].Nonce;

            var fullEapol = SerializeEapolForHashcat(messages);
            eapolData = fullEapol;
            keyDataLen = fullEapol.Length;

            string anonceHex = anonce != null ? Convert.ToHexString(anonce).ToLowerInvariant() : "";
            string snonceHex = snonce != null ? Convert.ToHexString(snonce).ToLowerInvariant() : "";
            string micHex = Convert.ToHexString(mic).ToLowerInvariant();
            string essidHex = bssidHex(ssid);
            string eapolHex = eapolData != null ? Convert.ToHexString(eapolData).ToLowerInvariant() : "";

            return $"WPA*02*{micHex}*{essidHex}*{bssidClean}*{snonceHex}*{anonceHex}*{eapolHex}*{keyDataLen}";
        }

        private static string bssidHex(string ssid)
        {
            byte[] ssidBytes = Encoding.UTF8.GetBytes(ssid);
            return Convert.ToHexString(ssidBytes).ToLowerInvariant();
        }

        private static byte[] SerializeEapolForHashcat(List<EapolFrame> frames)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            var lastFrame = frames.Last();

            bw.Write((byte)1);
            bw.Write((byte)3);
            bw.Write(BinaryPrimitives.ReadUInt16BigEndian(
                BitConverter.GetBytes(lastFrame.Length)));
            bw.Write(BinaryPrimitives.ReadUInt16BigEndian(
                BitConverter.GetBytes(lastFrame.KeyDescriptorType)));
            bw.Write(BinaryPrimitives.ReadUInt16BigEndian(
                BitConverter.GetBytes(lastFrame.KeyInfo)));
            bw.Write(BinaryPrimitives.ReadUInt16BigEndian(
                BitConverter.GetBytes((ushort)lastFrame.KeyLength)));
            bw.Write(lastFrame.ReplayCounter);
            bw.Write(lastFrame.Nonce);
            bw.Write(lastFrame.KeyIv);
            bw.Write(lastFrame.KeyRsc);
            bw.Write(lastFrame.KeyId);
            bw.Write(lastFrame.KeyMic);

            bw.Write((byte)0);
            bw.Write((byte)0);

            if (lastFrame.KeyData != null && lastFrame.KeyDataLength > 0)
                bw.Write(lastFrame.KeyData, 0, Math.Min(lastFrame.KeyDataLength, lastFrame.KeyData.Length));

            return ms.ToArray();
        }

        private static List<(DateTime Timestamp, byte[] Data)> ParsePcapFile(byte[] fileBytes, bool isSwapped)
        {
            var packets = new List<(DateTime, byte[])>();

            int offset = 24;

            while (offset + 16 <= fileBytes.Length)
            {
                uint tsSec = isSwapped
                    ? BinaryPrimitives.ReadUInt32BigEndian(fileBytes.AsSpan(offset, 4))
                    : BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(offset, 4));
                uint tsUsec = isSwapped
                    ? BinaryPrimitives.ReadUInt32BigEndian(fileBytes.AsSpan(offset + 4, 4))
                    : BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(offset + 4, 4));
                int inclLen = isSwapped
                    ? BinaryPrimitives.ReadInt32BigEndian(fileBytes.AsSpan(offset + 8, 4))
                    : BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(offset + 8, 4));
                int origLen = isSwapped
                    ? BinaryPrimitives.ReadInt32BigEndian(fileBytes.AsSpan(offset + 12, 4))
                    : BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(offset + 12, 4));

                offset += 16;

                if (inclLen <= 0 || inclLen > origLen || offset + inclLen > fileBytes.Length)
                    break;

                byte[] packetData = new byte[inclLen];
                Array.Copy(fileBytes, offset, packetData, 0, inclLen);

                var timestamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .AddSeconds(tsSec)
                    .AddMilliseconds(tsUsec / 1000.0);

                packets.Add((timestamp, packetData));
                offset += inclLen;
            }

            return packets;
        }

        private static EapolFrame? ParseEapolFrame(byte[] packetData, int eapolOffset, bool isSwapped)
        {
            if (packetData.Length < eapolOffset + 99)
                return null;

            try
            {
                int off = eapolOffset;

                byte version = packetData[off + 1];
                byte type = packetData[off + 2];
                ushort length = isSwapped
                    ? BinaryPrimitives.ReadUInt16BigEndian(packetData.AsSpan(off + 3, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(off + 3, 2));

                if (type != 3)
                    return null;

                ushort keyDescType = isSwapped
                    ? BinaryPrimitives.ReadUInt16BigEndian(packetData.AsSpan(off + 5, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(off + 5, 2));

                ushort keyInfo = isSwapped
                    ? BinaryPrimitives.ReadUInt16BigEndian(packetData.AsSpan(off + 7, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(off + 7, 2));

                uint keyLength = isSwapped
                    ? BinaryPrimitives.ReadUInt32BigEndian(packetData.AsSpan(off + 9, 4))
                    : BinaryPrimitives.ReadUInt32LittleEndian(packetData.AsSpan(off + 9, 4));

                byte[] replayCounter = new byte[8];
                Array.Copy(packetData, off + 13, replayCounter, 0, 8);

                byte[] nonce = new byte[32];
                Array.Copy(packetData, off + 21, nonce, 0, 32);

                byte[] keyIv = new byte[16];
                Array.Copy(packetData, off + 53, keyIv, 0, 16);

                byte[] keyRsc = new byte[8];
                Array.Copy(packetData, off + 69, keyRsc, 0, 8);

                byte[] keyId = new byte[8];
                Array.Copy(packetData, off + 77, keyId, 0, 8);

                byte[] keyMic = new byte[16];
                Array.Copy(packetData, off + 85, keyMic, 0, 16);

                ushort keyDataLen = isSwapped
                    ? BinaryPrimitives.ReadUInt16BigEndian(packetData.AsSpan(off + 101, 2))
                    : BinaryPrimitives.ReadUInt16LittleEndian(packetData.AsSpan(off + 101, 2));

                byte[] keyData = Array.Empty<byte>();
                int keyDataEnd = off + 103 + keyDataLen;

                if (keyDataLen > 0 && keyDataEnd <= packetData.Length)
                {
                    keyData = new byte[keyDataLen];
                    Array.Copy(packetData, off + 103, keyData, 0, keyDataLen);
                }

                return new EapolFrame(
                    version, type, length,
                    keyDescType, keyInfo, keyLength,
                    replayCounter, nonce, keyIv,
                    keyRsc, keyId, keyMic,
                    keyDataLen, keyData);
            }
            catch
            {
                return null;
            }
        }

        private static string? ExtractBssidFromDhcp(byte[] data, int dhcpOffset)
        {
            if (data.Length < dhcpOffset + 236)
                return null;

            try
            {
                byte[] chaddr = new byte[6];
                Array.Copy(data, dhcpOffset + 28, chaddr, 0, 6);

                bool allZero = chaddr.All(b => b == 0);
                if (allZero)
                    return null;

                return string.Join(":", chaddr.Select(b => b.ToString("X2")));
            }
            catch
            {
                return null;
            }
        }

        private static string FormatMac(byte[] data, int offset)
        {
            if (offset + 6 > data.Length)
                return "??";
            return string.Join(":", data.Skip(offset).Take(6).Select(b => b.ToString("X2")));
        }

        public HandshakeResult? GetHandshakeForAP(string bssid)
        {
            if (_capturedHandshakes.TryGetValue(bssid, out var result))
                return result;
            return null;
        }

        public bool ExportToHc22000(string outputPath, string ssid)
        {
            if (_capturedHandshakes.Count == 0)
                return false;

            using var writer = new StreamWriter(outputPath, false, Encoding.UTF8);

            foreach (var kvp in _capturedHandshakes)
            {
                if (!kvp.Value.IsValid)
                    continue;

                try
                {
                    string hc22000 = ConvertToHC22000(kvp.Value, ssid);
                    writer.WriteLine(hc22000);
                }
                catch
                {
                    continue;
                }
            }

            return true;
        }

        public List<HandshakeResult> GetAllValidHandshakes()
        {
            return _capturedHandshakes.Values.Where(h => h.IsValid).ToList();
        }
    }
}
