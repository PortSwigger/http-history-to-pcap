import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;

import java.net.*;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class BurpPcapWriter implements AutoCloseable {

    private static final int MSS = 65495;
    private static final MacAddress CLIENT_MAC_ADDRESS = MacAddress.getByName("00:62:75:72:70:31");
    private static final MacAddress SERVER_MAC_ADDRESS = MacAddress.getByName("00:62:75:72:70:32");
    private static final String CLIENT_IP4_ADDRESS = "127.0.0.1";
    private static final String SERVER_IP4_ADDRESS = "127.0.0.2";
    private static final String CLIENT_IP6_ADDRESS = "::1";
    private static final String UNKNOWN_IP4_ADDRESS = "192.0.2.123";

    private final PcapHandle handle;
    private final PcapDumper dumper;
    private final boolean forcePort80;
    private final boolean useRealIPs;
    private final AtomicInteger pktCounter;

    public BurpPcapWriter(String filename, boolean usePort80, boolean useRealIPs) throws Exception {
        this.handle = Pcaps.openDead(DataLinkType.EN10MB, 65535);
        this.dumper = handle.dumpOpen(filename);
        this.forcePort80 = usePort80;
        this.pktCounter = new AtomicInteger(0);
        this.useRealIPs = useRealIPs;
    }

    public void writeEntries(List<HttpRequestResponse> entries) throws Exception {
        for (int entryIdx = 0; entryIdx < entries.size(); entryIdx++) {
            HttpRequestResponse entry = entries.get(entryIdx);
            pktCounter.set(0);

            // Get entry data
            BurpEntryData entryData = determineEntryData(entryIdx, entry);
            Endpoint client = entryData.client();
            Endpoint server = entryData.server();
            Instant ts = entryData.ts();

            // TCP handshake
            writeHandshake(client, server, ts);

            // HTTP Request
            byte[] httpRequest = entry.request().toByteArray().getBytes();
            int clientSeq = writePacketsChunked(client, server, httpRequest, client.isn() + 1, server.isn() + 1, ts);

            // HTTP response
            byte[] httpResponse = (entry.response() != null) ? entry.response().toByteArray().getBytes() : null;
            int serverSeq = writePacketsChunked(server, client, httpResponse, server.isn() + 1, clientSeq, ts);

            // TCP teardown
            writeTeardown(client, server, serverSeq, clientSeq, ts);
        }
    }

    private int writePacketsChunked(Endpoint src, Endpoint dst, byte[] data, int srcSeq, int dstSeq, Instant ts) throws Exception {
        if (data != null && data.length > 0) {
            int offset = 0;
            // Source sends chunked data
            while (offset < data.length) {
                int len = Math.min(MSS, data.length - offset);
                byte[] payload = Arrays.copyOfRange(data, offset, offset + len);
                write(packet(TcpFlag.PSH_ACK, src, dst, srcSeq, dstSeq, payload), ts);
                srcSeq += len;
                offset += len;
            }
            // Destination acknowledges all received data
            write(packet(TcpFlag.ACK, dst, src, dstSeq, srcSeq, null), ts);
        }
        return srcSeq;
    }

    private void writeHandshake(Endpoint client, Endpoint server, Instant ts) throws Exception {
        write(packet(TcpFlag.SYN, client, server, client.isn(), 0, null), ts);
        write(packet(TcpFlag.SYN_ACK, server, client, server.isn(), client.isn() + 1,null), ts);
        write(packet(TcpFlag.ACK, client, server, client.isn() + 1, server.isn() + 1, null), ts);
    }

    private void writeTeardown(Endpoint client, Endpoint server, int serverSeq, int clientSeq, Instant ts) throws Exception {
        write(packet(TcpFlag.FIN_ACK, server, client, serverSeq, clientSeq, null), ts);
        write(packet(TcpFlag.FIN_ACK, client, server, clientSeq, serverSeq, null), ts);
        write(packet(TcpFlag.ACK, server, client, serverSeq + 1, clientSeq + 1, null), ts);
    }

    private void write(Packet packet, Instant ts) throws Exception {
        dumper.dump(packet, Timestamp.from(ts.plusMillis(pktCounter.getAndIncrement())));
    }

    private Packet packet(TcpFlag flag, Endpoint src, Endpoint dst, int seq, int ack, byte[] payload) throws UnknownHostException {
        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .payloadBuilder(payload == null ? null : new UnknownPacket.Builder().rawData(payload))
                .srcAddr(src.inetSocketAddress().getAddress())
                .dstAddr(dst.inetSocketAddress().getAddress())
                .srcPort(TcpPort.getInstance((short) src.inetSocketAddress().getPort()))
                .dstPort(TcpPort.getInstance((short) dst.inetSocketAddress().getPort()))
                .sequenceNumber(seq)
                .acknowledgmentNumber(ack)
                .window((short) 65535)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        switch (flag) {
            case SYN_ACK:
                tcpBuilder.ack(true);
            case SYN:
                TcpMaximumSegmentSizeOption mssOption = new TcpMaximumSegmentSizeOption.Builder()
                        .maxSegSize((short) MSS)
                        .length((byte) 4)
                        .build();
                tcpBuilder.syn(true)
                        .options(List.of(mssOption));
                break;
            case ACK: tcpBuilder.ack(true); break;
            case PSH_ACK: tcpBuilder.psh(true).ack(true); break;
            case FIN_ACK: tcpBuilder.fin(true).ack(true); break;
            case FIN: tcpBuilder.fin(true); break;
        }

        InetAddress srcAddress = src.inetSocketAddress().getAddress();
        InetAddress dstAddress = dst.inetSocketAddress().getAddress();
        EtherType type;
        Packet.Builder ipBuilder;

        if (srcAddress instanceof Inet6Address && dstAddress instanceof Inet6Address) {
            type = EtherType.IPV6;
            ipBuilder = new IpV6Packet.Builder()
                    .version(IpVersion.IPV6)
                    .srcAddr((Inet6Address) srcAddress)
                    .dstAddr((Inet6Address) dstAddress)
                    .payloadBuilder(tcpBuilder)
                    .correctLengthAtBuild(true);
        } else {
            Inet4Address src4, dst4;
            try {
                src4 = (Inet4Address) srcAddress;
            } catch (ClassCastException e) {
                src4 = (Inet4Address) InetAddress.getByName(UNKNOWN_IP4_ADDRESS);
            }
            try {
                dst4 = (Inet4Address) dstAddress;
            } catch (ClassCastException e) {
                dst4 = (Inet4Address) InetAddress.getByName(UNKNOWN_IP4_ADDRESS);
            }
            type = EtherType.IPV4;
            ipBuilder = new IpV4Packet.Builder()
                    .version(IpVersion.IPV4)
                    .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                    .ttl((byte) 64)
                    .protocol(IpNumber.TCP)
                    .srcAddr(src4)
                    .dstAddr(dst4)
                    .payloadBuilder(tcpBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);
        }

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .srcAddr(src.macAddress())
                .dstAddr(dst.macAddress())
                .type(type)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);
        return etherBuilder.build();
    }

    private BurpEntryData determineEntryData(int entryIdx, HttpRequestResponse entry) {
        HttpService svc = entry.request().httpService();
        String clientIp;
        String serverIp;

        serverIp = useRealIPs ? svc.ipAddress() : SERVER_IP4_ADDRESS;
        try {
            InetAddress address = InetAddress.getByName(serverIp);
            clientIp = address instanceof Inet6Address ? CLIENT_IP6_ADDRESS : CLIENT_IP4_ADDRESS;
        } catch (Exception ignored) {
            serverIp = SERVER_IP4_ADDRESS;
            clientIp = CLIENT_IP4_ADDRESS;
        }

        InetSocketAddress serverAddress = new InetSocketAddress(serverIp, forcePort80 ? 80 : svc.port());
        InetSocketAddress clientAddress = new InetSocketAddress(clientIp, 10000 + entryIdx);
        Endpoint server = new Endpoint(SERVER_MAC_ADDRESS, serverAddress, 50000 + entryIdx * 10);
        Endpoint client = new Endpoint(CLIENT_MAC_ADDRESS, clientAddress, 10000 + entryIdx * 10);

        Instant ts;
        Optional<TimingData> optional = entry.timingData();
        if (optional.isPresent()) {
            ts = optional.get().timeRequestSent().toInstant();
        } else {
            ts = Instant.ofEpochMilli(System.currentTimeMillis() + entryIdx * 1000L);
        }

        return new BurpEntryData(client, server, ts);
    }

    @Override
    public void close() {
        dumper.close();
        handle.close();
    }

    enum TcpFlag {
        SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK, FIN
    }

    record BurpEntryData(Endpoint client, Endpoint server, Instant ts) {}
    record Endpoint(MacAddress macAddress, InetSocketAddress inetSocketAddress, int isn) {}
}