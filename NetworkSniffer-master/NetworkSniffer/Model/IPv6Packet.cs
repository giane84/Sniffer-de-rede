using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace NetworkSniffer.Model
{
    public class IPv6Packet
    {
        #region Fields
        private byte[] byteIPv6Header;
        private byte[] byteIPv6Message;
        private uint packetID;
        #endregion

        #region Constructors

        public IPv6Packet(byte[] byteBuffer, int length)
        {
            try
            {
                #region Buffer parsing
                uint byteVersionAndTrafficClassAndFlowLabel;
                uint bytePayloadLengthAndNextHeaderAndHopLimit;

                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

                BinaryReader binaryReader = new BinaryReader(memoryStream);

                byteVersionAndTrafficClassAndFlowLabel = binaryReader.ReadUInt32();

                // 4 bits
                Version = (byte)(byteVersionAndTrafficClassAndFlowLabel >> 4);

                // Next 2 bytes
                TrafficClass = (byte)(byteVersionAndTrafficClassAndFlowLabel << 4);
                TrafficClass >>= 16;

                // Next 5 bytes
                FlowLabel = (byte)(byteVersionAndTrafficClassAndFlowLabel << 16);
                FlowLabel >>= 40;

                bytePayloadLengthAndNextHeaderAndHopLimit = binaryReader.ReadUInt32();
                // Next 4 bytes
                PayloadLength = (byte)(bytePayloadLengthAndNextHeaderAndHopLimit >> 32);

                // Next 2 bytes
                NextHeader = (byte)(bytePayloadLengthAndNextHeaderAndHopLimit << 32);
                NextHeader >>= 16;

                // Next 2 bytes
                HopLimit = (byte)(bytePayloadLengthAndNextHeaderAndHopLimit << 16);
                HopLimit >>= 16;

                // Next 16 bytes
                SourceIPAddress = new IPAddress(binaryReader.ReadBytes(16));

                // Next 16 bytes
                DestinationIPAddress = new IPAddress(binaryReader.ReadBytes(16));

                // Copy header from byteBuffer to byteIPHeader
                byteIPv6Header = new byte[PayloadLength];
                Array.Copy(byteBuffer, byteIPv6Header, PayloadLength);

                // Copy message data from byteBuffer to byteIPMessage
                byteIPv6Message = new byte[length - PayloadLength];
                Array.Copy(byteBuffer, PayloadLength, byteIPv6Message, 0, length - PayloadLength);

                IPv6Header = new List<IPv6Header>();
                #endregion
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        public byte Version { get; set; }

        public ushort TrafficClass { get; set; }

        public ushort FlowLabel { get; set; }

        public ushort PayloadLength { get; set; }

        public ushort NextHeader { get; set; }

        public ushort HopLimit { get; set; }

        public IPAddress SourceIPAddress { get; set; }

        public IPAddress DestinationIPAddress { get; set; }

        public byte[] ByteIPv6Header
        {
            get
            {
                return byteIPv6Header;
            }
        }

        public byte[] ByteIPv6Message
        {
            get
            {
                return byteIPv6Message;
            }
        }

        public uint PacketID
        {
            get
            {
                return packetID;
            }
            set
            {
                packetID = value;
            }
        }

        public List<IPv6Header> IPv6Header { get; set; }
        #endregion
    }
}
