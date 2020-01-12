/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_UDP = 0x800;
#define MTU 1500
#define maximumsize 32
#define buffersize 32

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header payload_t{
    bit<maximumsize>    input;
}
header udp_t {
    bit<64> hahaha;
}

struct metadata {
    bit<32> packet_length;
    bit<maximumsize> payloadtmp;
    bit<32> encodingnumber;/****s1 register2 index0****/
    bit<32> encodingpointer;/****s1 register2 index1****/
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    payload_t    payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.packet_length = standard_metadata.packet_length;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.packet_length = meta.packet_length - 14;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.packet_length = meta.packet_length - 20;
        transition parse_udp;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.packet_length = meta.packet_length - 8;
        transition parse_payload;
    }

    state parse_payload{
        packet.extract(hdr.payload);
        transition accept;

    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    register<bit<maximumsize>>(buffersize) registerA;
    register<bit<32>>(2) pointer;


    bit<maximumsize> registertmp = 1;
    bit<32> registerindex = 32w0x00;

    action buffer(){
        pointer.read(meta.encodingnumber, 0);

        if(meta.encodingnumber == buffersize){
            meta.encodingnumber = buffersize - 1;
        }
        registerA.write(meta.encodingnumber, meta.payloadtmp);
        meta.encodingnumber = meta.encodingnumber + 1;
        pointer.write(0,meta.encodingnumber);
    }

    action encoding(){
        pointer.read(meta.encodingpointer, 1);
        registerA.read(registertmp, meta.encodingpointer);
        registerA.write(meta.encodingpointer, 0);

        //registerA.read(registertmp, 0);

        if(registertmp != 0){
            meta.payloadtmp = registertmp ^ meta.payloadtmp;
            meta.encodingpointer = meta.encodingpointer + 1;            
        }

        if(meta.encodingpointer == buffersize){
            meta.encodingpointer = 0;
        }
        hdr.payload.input = meta.payloadtmp; 
        pointer.write(1,meta.encodingpointer);
    }

    action decoding(){
        pointer.read(meta.encodingpointer, 1);
        registerA.read(registertmp, meta.encodingpointer);
        registerA.write(meta.encodingpointer, 0); 

        //registerA.read(registertmp, 0);
        
        if(registertmp != 0){
            meta.payloadtmp = registertmp ^ meta.payloadtmp;
            meta.encodingpointer = meta.encodingpointer + 1;            
        }
        
        if(meta.encodingpointer == buffersize){
            meta.encodingpointer = 0;
        }
        hdr.payload.input = meta.payloadtmp; 
        pointer.write(1,meta.encodingpointer);
    }

    action forward(macAddr_t dstAddr, egressSpec_t port){
        hdr.ethernet.srcAddr = 0x000000000333;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;     
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table encoding_match {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            buffer;
            encoding;
            drop;     
            NoAction;
        }
        const entries = {
            0x000000000101: buffer();
            0x00000000010b: encoding();
        }        
    }
    table decoding_match {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            buffer;
            decoding; 
            drop;    
            NoAction;
        }
        const entries = {
            0x000000000202: buffer();
            0x000000000216: decoding();
        }
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.payload.isValid()){
                meta.payloadtmp = hdr.payload.input;
                encoding_match.apply(); 
            }
            ipv4_forward.apply();
            if(hdr.payload.isValid()){
                decoding_match.apply();
            }            
        }
        if(registertmp == 0){
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {



    apply {
        
            
        
    }
}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;