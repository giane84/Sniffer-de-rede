using System;
using System.Net;
using System.Net.Sockets;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class contains methods used to start and stop receiving session and capture data
    /// </summary>
    class InterfaceMonitor
    {
        #region Fields
        private const uint MTU = 1024 * 64;
        private byte[] byteBufferData;
        private Socket socket;
        private IPAddress ipAddress;

        public ProtocolType Undefined { get; }
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of the InterfaceMonitor class
        /// </summary>
        /// <param name="ip">IP address on which packets need to be captured</param>
        public InterfaceMonitor(string ip)
        {
            byteBufferData = new byte[MTU];
            //socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IP);
            // socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IPv6);
            socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.Unspecified);
            ipAddress = IPAddress.Parse(ip);
        }
        #endregion

        #region Methods
        /// <summary>
        /// Opens new socket and starts receiving data
        /// </summary>
        public void StartCapture()
        {
            /* Bind the socket to selected IP address */
            socket.Bind(new IPEndPoint(ipAddress, 0));

            /* Socket options apply only to IP packets */
            //socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.HeaderIncluded, false);

            byte[] byteTrue = new byte[4] { 1, 0, 0, 0 };
            byte[] byteOut = new byte[4];
            /* ReceiveAll implies that all incoming and outgoing packets on the interface are captured.
             * Second option should be TRUE */
            socket.IOControl(IOControlCode.ReceiveAll, byteTrue, byteOut);

            byteBufferData = new byte[MTU];
            socket.BeginReceive(byteBufferData, 0, byteBufferData.Length,
                                SocketFlags.None, new AsyncCallback(this.ReceiveData), null);
        }

        /// <summary>
        /// Used to receive and process every new packet and receive the next one
        /// </summary>
        private void ReceiveData(IAsyncResult asyncResult)
        {
            try
            {
                int bytesReceived = socket.EndReceive(asyncResult);

                byte[] receivedData = new byte[bytesReceived];
                Array.Copy(byteBufferData, 0, receivedData, 0, bytesReceived);

                IPv6Packet newPacket = new IPv6Packet(receivedData, bytesReceived);
                if (newPacketEventHandler != null)
                {
                    newPacketEventHandler(newPacket);
                }
                
                socket.BeginReceive(byteBufferData, 0, byteBufferData.Length,
                                    SocketFlags.None, new AsyncCallback(this.ReceiveData), null);
            }
            catch
            {
                StopCapture();
            }

        }

        /// <summary>
        /// Used to stop current session by closing socket
        /// </summary>
        public void StopCapture()
        {
            if (socket != null)
            {
                socket.Close();
                socket = null;
                ipAddress = null;
            }
        }
        #endregion

        #region Event handlers
        public event NewPacketEventHandler newPacketEventHandler;

        public delegate void NewPacketEventHandler(IPv6Packet newPacket);
        #endregion
    }
}
