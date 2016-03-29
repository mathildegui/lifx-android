package com.codetaku.lifx;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * LifX LAN Protocol implementation for Android
 */
public class LifXService {
    /**
     * Default port for LIFX
     */
    private static final int LIFX_PORT = 56700;
    /**
     * The unique source identifier for this session
     */
    private final int source = (int) (Math.random() * Long.MAX_VALUE);
    /**
     * This device's ip address. We will ignore datagrams from this ip
     */
    private static String myAddress = null;
    private static String broadcastAddress = null;

    /**
     * If this service is currently listening for responses from other LifX devices
     */
    private boolean running = false;
    /**
     * The current sequence id of messages
     */
    private byte sequence = 1;

    /**
     * What devices were discovered
     */
    private final Set<Long> detectedDevices = new HashSet<>();

    /**
     * Set the Light Bulb to ON
     */
    public static final int STATE_ON = 65535;
    /**
     * Set the Light Bulb to OFF
     */
    public static final int STATE_OFF = 0;

    /**
     * In this thread we read the udp messages
     */
    private Thread mUDPListeningThread;
    /**
     * In this thread we send the udp messages
     */
    private ExecutorService mSingleThreadExecutorService = Executors.newSingleThreadExecutor();

    /**
     * Callbacks
     */
    private List<LifXListener> mListeners = new ArrayList<>();

    /**
     * Android Handler to send callbacks on the main thread
     */
    private Handler mHandler;

    /**
     * Will get the wifi interface ip address and broadcast address. Make sure you are connected to wifi.
     */
    public LifXService() throws NotConnectedException {
        /**
         * From http://stackoverflow.com/questions/2993874/android-broadcast-address
         * @return
         */

        System.setProperty("java.net.preferIPv4Stack", "true");
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface ni = en.nextElement();
                if (!ni.isLoopback()) {
                    for (InterfaceAddress interfaceAddress : ni.getInterfaceAddresses()) {
                        if (interfaceAddress == null || interfaceAddress.getBroadcast() == null || interfaceAddress.getAddress().getAddress().length != 4) {
                            continue;
                        }
                        myAddress = interfaceAddress.getAddress().toString().substring(1);
                        broadcastAddress = interfaceAddress.getBroadcast().toString().substring(1);
                        break;
                    }
                }

                if (myAddress != null) {
                    break;
                }
            }
        } catch (SocketException ex) {}

        mHandler = new Handler(Looper.getMainLooper());

        if (myAddress == null || broadcastAddress == null) {
            throw new NotConnectedException();
        }
    }

    public void addListener(LifXListener listener) {
        mListeners.add(listener);
    }

    public void removeListener(LifXListener listener) {
        mListeners.remove(listener);
    }

    /**
     * Starts listening for responses and will call detectDevices()
     */
    public void startListener() {
        running = true;
        startListenerThread();
        detectDevices();
    }

    /**
     * Stops listening for responses. Commands will still work
     */
    public void stopListener() {
        running = false;

        if (mUDPListeningThread != null && mUDPListeningThread.isAlive()) {
            mUDPListeningThread.interrupt();
        }
    }

    /**
     * Alias for broadcastMessage(DeviceMessageType.GetService, true);
     */
    public void detectDevices() {
        broadcastMessage(DeviceMessageType.GetService, true);
    }

    /**
     * Helper method to turn off all light bulbs
     */
    public void turnOffAllLightBulbs() {
        Bundle b = new Bundle();
        b.putInt("level" , STATE_OFF);

        broadcastMessage(DeviceMessageType.SetPower, true, b);
    }

    /**
     * Helper method to turn on all light bulbs
     */
    public void turnOnAllLightBulbs() {
        Bundle b = new Bundle();
        b.putInt("level" , STATE_ON);

        broadcastMessage(DeviceMessageType.SetPower, true, b);
    }

    /**
     * Helper method to turn off a light bulb
     * @param target - the mac address of the light bulb
     */
    public void turnOffLightBulb(long target) {
        Bundle b = new Bundle();
        b.putInt("level" , STATE_OFF);

        sendMessage(target, DeviceMessageType.SetPower, true, b);
    }

    /**
     * Helper method to turn on a light bulb
     * @param target - the mac address of the light bulb
     */
    public void turnOnLightBulb(long target) {
        Bundle b = new Bundle();
        b.putInt("level" , STATE_OFF);

        sendMessage(target, DeviceMessageType.SetPower, true, b);
    }

    /**
     * Helper method to change the color on all the light bulbs
     * @param hue - values from 0 - 65535 mapped to 0 - 360
     * @param saturation - values from 0 - 65535
     * @param brightness - values from 0 - 65535
     * @param temperature - values from 0 - 65535
     * @param duration - the fading duration in milliseconds
     */
    public void changeColorForAll(int hue, int saturation, int brightness, int temperature, long duration) {
        Bundle b = new Bundle();
        b.putInt("hue" , hue);
        b.putInt("saturation" , saturation);
        b.putInt("brightness" , brightness);
        b.putInt("kelvin" , temperature);
        b.putLong("duration" , duration);

        broadcastMessage(DeviceMessageType.SetColor, true, b);
    }

    /**
     * Helper method to change the color on a light bulb
     * @param target - the mac address of the light bulb
     * @param hue - values from 0 - 65535 mapped to 0 - 360
     * @param saturation - values from 0 - 65535
     * @param brightness - values from 0 - 65535
     * @param temperature - values from 0 - 65535
     * @param duration - the fading duration in milliseconds
     */
    public void changeColor(long target, int hue, int saturation, int brightness, int temperature, long duration) {
        Bundle b = new Bundle();
        b.putInt("hue" , hue);
        b.putInt("saturation" , saturation);
        b.putInt("brightness" , brightness);
        b.putInt("kelvin" , temperature);
        b.putLong("duration" , duration);

        sendMessage(target, DeviceMessageType.SetColor, true, b);
    }

    /**
     * Sends a message to all the light bulbs
     * @param messageType - the message type
     * @param requestResponse - true if you want a state response. false otherwise
     */
    public void broadcastMessage(DeviceMessageType messageType, boolean requestResponse) {
        sendMessage(0, messageType, requestResponse, null);
    }

    /**
     * Sends a message to a specific light bulb
     * @param target - the mac address of the light bulb
     * @param messageType - the message type
     * @param requestResponse - true if you want a state response. false otherwise
     */
    public void sendMessage(long target, DeviceMessageType messageType, boolean requestResponse) {
        sendMessage(target, messageType, requestResponse, null);
    }

    /**
     * Sends a message to all the light bulbs
     * @param messageType - the message type
     * @param requestResponse - true if you want a state response. false otherwise
     * @param parameters - the parameters (see {@link DeviceMessageType}
     */
    public void broadcastMessage(DeviceMessageType messageType, boolean requestResponse, Bundle parameters) {
        sendMessage(0, messageType, requestResponse, parameters);
    }

    /**
     * Sends a message to a specific light bulb
     * @param target - the mac address of the light bulb
     * @param messageType - the message type
     * @param requestResponse - true if you want a state response. false otherwise
     * @param parameters - the parameters (see {@link DeviceMessageType}
     */
    public synchronized void sendMessage(long target, DeviceMessageType messageType, boolean requestResponse, Bundle parameters) {
        int parametersLength = 0;

        if (messageType.getParameters() != null) {
            for (Parameter param : messageType.getParameters()) {
                parametersLength += (param.byteLength == -1) ? param.type.byteLength : param.byteLength;
            }
        }

        int size = 36 + parametersLength;
        ByteBuffer datagram = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        datagram.put(getFrame(size, target == 0 ? true : false));
        datagram.put(getFrameAddress(target, true, requestResponse, sequence++));
        datagram.put(getProtocolHeader(messageType.code));

        if (parametersLength > 0) {
            for (Parameter param : messageType.getParameters()) {
                byte[] paramValue = getParamValue(param, parameters);
                datagram.put(paramValue);
            }
        }

        sendUDPMessage(datagram.array());
    }

    /**
     * Translates parameters into bytes
     * @param param - the parameter you want translated
     * @param parameters - the list of parameters
     * @return the parameter value in bytes
     */
    private byte[] getParamValue(Parameter param, Bundle parameters) {
        int size = (param.byteLength == -1) ? param.type.byteLength : param.byteLength;
        ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);

        if (param.type == ReturnType.String) {
            String stringValue = parameters.getString(param.name, "");

            if (stringValue.length() > param.byteLength) {
                stringValue = stringValue.substring(0, param.byteLength);
            }

            buffer.put(stringValue.getBytes());
        }
        else if (param.type == ReturnType.INT16) {
            buffer.putShort(parameters.getShort(param.name, (short) 0));
        }
        else if (param.type == ReturnType.FLOAT) {
            buffer.putFloat(parameters.getFloat(param.name, 0f));
        }
        else if (param.type == ReturnType.ByteArray) {
            byte[] baValue = parameters.getByteArray(param.name);

            if (baValue == null) {
                baValue = new byte[size];
            }
            else if (baValue.length < size) {
                byte[] newArray = new byte[size];
                System.arraycopy(baValue, 0, newArray, 0, baValue.length);

                baValue = newArray;
            }

            buffer.put(baValue, 0, size);
        }
        else if (param.type == ReturnType.UINT8) {
            buffer.put((byte) parameters.getShort(param.name, (short) 0));
        }
        else if (param.type == ReturnType.UINT16) {
            buffer.putShort((short) parameters.getInt(param.name, 0));
        }
        else if (param.type == ReturnType.UINT32) {
            buffer.putInt((int) parameters.getLong(param.name, 0));
        }
        else if (param.type == ReturnType.UINT64) {
            buffer.putLong(parameters.getLong(param.name, 0));
        }

        return buffer.array();
    }

    /**
     * Gets the frame part of the message header
     * @param size - the size of the whole message
     * @param tagged - true if the message is sent to all devices. false if it's only sent to a specific device
     * @return the frame part of the message header in bytes
     */
    private byte[] getFrame(int size, boolean tagged) {
        byte protocolAndFlags = 20;

        if (tagged) {
            protocolAndFlags += 32;
        }

        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort((short) size);
        buffer.put((byte) 0);
        buffer.put(protocolAndFlags);
        buffer.putInt(source);

        return buffer.array();
    }

    /**
     * Gets the frame address part of the message header
     * @param target - the mac address of the device; 0 for all devices
     * @param ackRequired - true if you want an Acknowledgement message; false otherwise
     * @param resRequired - true if you want a State response; false otherwise
     * @param sequence - the sequence number of this message
     * @return the frame address part of the message header in bytes
     */
    private byte[] getFrameAddress(long target, boolean ackRequired, boolean resRequired, int sequence) {
        ByteBuffer buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(target);
        buffer.position(14);

        byte ar = 0;
        if (resRequired) {
            ar += 1;
        }
        if (ackRequired) {
            ar += 2;
        }

        buffer.put(ar);
        buffer.put((byte) sequence);

        return buffer.array();
    }

    /**
     * Gets the protocol header of the message header
     * @param messageType - the id of the message type (see {@link DeviceMessageType}
     * @return the protocol part of the message header in bytes
     */
    private byte[] getProtocolHeader(int messageType) {
        ByteBuffer buffer = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN);
        buffer.position(8);
        buffer.putShort((short) messageType);

        return buffer.array();
    }

    /**
     * Sends a message over to the broadcast address
     * @param message - the message in bytes
     */
    private synchronized void sendUDPMessage(final byte[] message) {
        mSingleThreadExecutorService.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    DatagramSocket clientSocket = new DatagramSocket();

                    clientSocket.setBroadcast(true);
                    InetAddress address = InetAddress.getByName(broadcastAddress);

                    DatagramPacket sendPacket = new DatagramPacket(message, message.length, address, LIFX_PORT);
                    clientSocket.send(sendPacket);

                    clientSocket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
//        if (mUDPSendingThread == null && mUDPSendingThread.isAlive()) {
//            return;
//        }
//
//        ExecutorSe
//        mUDPSendingThread = new Thread() {
//            public void run() {
//                try {
//                    DatagramSocket clientSocket = new DatagramSocket();
//
//                    clientSocket.setBroadcast(true);
//                    InetAddress address = InetAddress.getByName(broadcastAddress);
//
//                    while (!mMessageQueue.isEmpty()) {
//                        byte[] message = mMessageQueue.poll();
//                        DatagramPacket sendPacket = new DatagramPacket(message, message.length, address, LIFX_PORT);
//                        clientSocket.send(sendPacket);
//                    }
//
//                    clientSocket.close();
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            }
//        };
//
//        mUDPSendingThread.start();
    }

    /**
     * Starts the listener Thread
     */
    private void startListenerThread() {
        if (mUDPListeningThread != null && !mUDPListeningThread.isInterrupted()) {
            return;
        }

        mUDPListeningThread = new Thread() {
            public void run() {
                try {
                    InetAddress broadcastIP = InetAddress.getByName(broadcastAddress);
                    Integer port = LIFX_PORT;
                    DatagramSocket socket = new DatagramSocket(port, broadcastIP);
                    socket.setBroadcast(true);
                    byte[] recvBuf = new byte[1000];

                    while (running && !isInterrupted()) {
                        DatagramPacket packet = new DatagramPacket(recvBuf, recvBuf.length);
                        Log.e("UDP", "Waiting for UDP broadcast");
                        socket.receive(packet);

                        String senderIP = packet.getAddress().getHostAddress();

                        Log.e("UDP", "Got UDB broadcast from " + senderIP);

                        if (senderIP.equals(myAddress)) {
                            continue;
                        }

                        final byte[] data = new byte[1000];
                        System.arraycopy(recvBuf, 0, data, 0, recvBuf.length);

                        new Thread() {
                            public void run() {
                                processDatagram(data);
                            }
                        }.start();
                    }

                    socket.close();
                    //if (!shouldListenForUDPBroadcast) throw new ThreadDeath();
                } catch (Exception e) {
                    Log.i("UDP", "no longer listening for UDP broadcasts cause of error " + e.getMessage());
                }
            }
        };
        mUDPListeningThread.start();
    }

    /**
     * Decodes a datagram
     * @param data
     */
    private void processDatagram(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        if (data.length < 2) {
            return;
        }

        int size = buffer.getShort();

        if (data.length < size) {
            return;
        }

        short protocolAndOthers = buffer.getShort();

        if (protocolAndOthers % 2048 != 1024) {
            // Not a LifX device?
            return;
        }

        int readSource = buffer.getInt();

        if (readSource != source) {
            // Not meant for this device
            return;
        }

        long target = buffer.getLong();
        buffer.getShort(); // Reserved
        buffer.getShort(); // Reserved
        buffer.getShort(); // Reserved
        buffer.get(); // Reserved
        int sequence = buffer.get() & 0xFF;
        buffer.getLong(); // Reserved
        int type = buffer.getShort() & 0xFFFF;
        buffer.getShort(); // Reserved

        DeviceMessageType messageType = DeviceMessageType.fromCode(type);

        if (messageType == null) {
            // Huh?
            return;
        }

        Log.i("LifXService", "Device Message: " + messageType.name() + " Sequence: " + sequence + " From " + target);

        Bundle parameters = new Bundle();
        if (messageType.getParameters() != null && messageType.getParameters().length > 0) {
            for (Parameter param : messageType.getParameters()) {
                if (param.type == ReturnType.String) {
                    byte[] stringBytes = new byte[param.byteLength];
                    buffer.get(stringBytes, 0, stringBytes.length);
                    String stringValue = new String(stringBytes);

                    parameters.putString(param.name, stringValue);
                }
                else if (param.type == ReturnType.INT16) {
                    parameters.putShort(param.name, buffer.getShort());
                }
                else if (param.type == ReturnType.FLOAT) {
                    parameters.putFloat(param.name, buffer.getFloat());
                }
                else if (param.type == ReturnType.ByteArray) {
                    byte[] byteArray = new byte[param.byteLength];
                    buffer.get(byteArray, 0, byteArray.length);
                    parameters.putByteArray(param.name, byteArray);
                }
                else if (param.type == ReturnType.UINT8) {
                    parameters.putInt(param.name, buffer.get() & 0xFF);
                }
                else if (param.type == ReturnType.UINT16) {
                    parameters.putInt(param.name, buffer.getShort() & 0xFFFF);
                }
                else if (param.type == ReturnType.UINT32) {
                    parameters.putLong(param.name, buffer.getInt() & 0xFFFFFFFF);
                }
                else if (param.type == ReturnType.UINT64) {
                    parameters.putLong(param.name, buffer.getLong());
                }
            }

            Log.i("LifXService", "Parameters: " + parameters.toString());
        }

        if (messageType == DeviceMessageType.StateService) {
            if (!detectedDevices.contains(target)) {
                detectedDevices.add(target);
                sendNewDeviceDetectedEvent(target);
            }
        }
    }

    /**
     * Calls all the listeners with the new event
     * @param target
     */
    private void sendNewDeviceDetectedEvent(final long target) {
        for (final LifXListener listener : mListeners) {
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    listener.onNewDeviceDetect(target);
                }
            });
        }
    }

    public enum DeviceMessageType {
        GetService(2),
        StateService(3, new Parameter("service", ReturnType.UINT8), new Parameter("port", ReturnType.UINT32)),
        GetHostInfo(12),
        StateHostInfo(13, new Parameter("signal", ReturnType.FLOAT), new Parameter("tx", ReturnType.UINT32), new Parameter("rx", ReturnType.UINT32), new Parameter("reserved", ReturnType.INT16)),
        GetHostFirmware(15, new Parameter("build", ReturnType.UINT64), new Parameter("reserved", ReturnType.UINT64), new Parameter("version", ReturnType.UINT32)),
        GetWifiInfo(16),
        StateWifiInfo(17, new Parameter("signal", ReturnType.FLOAT), new Parameter("tx", ReturnType.UINT32), new Parameter("rx", ReturnType.UINT32), new Parameter("reserved", ReturnType.INT16)),
        GetWifiFirmware(19, new Parameter("build", ReturnType.UINT64), new Parameter("reserved", ReturnType.UINT64), new Parameter("version", ReturnType.UINT32)),
        GetPower(20),
        SetPower(21, new Parameter("level", ReturnType.UINT16)),
        StatePower(22, new Parameter("level", ReturnType.UINT16)),
        GetLabel(23),
        SetLabel(24, new Parameter("label", ReturnType.String, 16)),
        StateLabel(25, new Parameter("label", ReturnType.String, 16)),
        GetVersion(32),
        StateVersion(33, new Parameter("vendor", ReturnType.UINT32), new Parameter("product", ReturnType.UINT32), new Parameter("version", ReturnType.UINT32)),
        GetInfo(34),
        StateInfo(35, new Parameter("time", ReturnType.UINT64), new Parameter("uptime", ReturnType.UINT64), new Parameter("downtime", ReturnType.UINT64)),
        Acknowledgement(45),
        GetLocation(48),
        StateLocation(50, new Parameter("location", ReturnType.ByteArray, 16), new Parameter("label", ReturnType.String, 32), new Parameter("updated_at", ReturnType.UINT64)),
        GetGroup(51),
        StateGroup(53, new Parameter("group", ReturnType.ByteArray, 16), new Parameter("label", ReturnType.String, 32), new Parameter("updated_at", ReturnType.UINT64)),
        EchoRequest(58, new Parameter("payload", ReturnType.ByteArray, 64)),
        EchoRespone(59, new Parameter("payload", ReturnType.ByteArray, 64)),
        Get(101),
        SetColor(102, new Parameter("reserved", ReturnType.UINT8), new Parameter("hue", ReturnType.UINT16), new Parameter("saturation", ReturnType.UINT16),
                new Parameter("brightness", ReturnType.UINT16), new Parameter("kelvin", ReturnType.UINT16), new Parameter("duration", ReturnType.UINT32)),
        State(107, new Parameter("reserved", ReturnType.UINT8), new Parameter("hue", ReturnType.UINT16), new Parameter("saturation", ReturnType.UINT16),
                new Parameter("brightness", ReturnType.UINT16), new Parameter("kelvin", ReturnType.UINT16), new Parameter("duration", ReturnType.UINT32)),
        GetPower116(116),
        SetPower117(117, new Parameter("level", ReturnType.UINT16), new Parameter("duration", ReturnType.UINT32)),
        StatePower118(118, new Parameter("level", ReturnType.UINT16));

        private int code;
        private Parameter[] parameters;

        DeviceMessageType(int code, Parameter... parameters) {
            this.code = code;
            this.parameters = parameters;
        }

        public int getCode() {
            return code;
        }

        public Parameter[] getParameters() {
            return parameters;
        }

        public static DeviceMessageType fromCode(int code) {
            for (DeviceMessageType dmt : DeviceMessageType.values()) {
                if (dmt.code == code) {
                    return dmt;
                }
            }

            return null;
        }
    }

    private static class Parameter {
        private ReturnType type;
        private int byteLength = -1;
        private String name;

        public Parameter(String name, ReturnType type) {
            this.name = name;
            this.type = type;
        }

        public Parameter(String name, ReturnType type, int length) {
            this.name = name;
            this.type = type;
            this.byteLength = length;
        }
    }

    private enum ReturnType {
        String, UINT32(4), UINT16(2), UINT64(4), UINT8(1), FLOAT(4), INT16(2), ByteArray;

        private int byteLength = 0;

        ReturnType(int byteLength) {
            this.byteLength = byteLength;
        }

        ReturnType() {

        }
    }

    public interface LifXListener {
        void onNewDeviceDetect(long address);
    }
}
