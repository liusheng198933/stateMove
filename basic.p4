/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_FLOWS 8

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MYTMP = 0x1212;
const bit<16> TYPE_MODE = 0x1233;
const bit<9> cpu_port = 64;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<48> time_t;
typedef bit<16> tmp_t;
typedef bit<32> flowid_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> state_t;

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

header timestamp_t {
    tmp_t ptp;
    tmp_t rtp;
    tmp_t ttp;
    flowid_t fid;
}

header mode_t {
    bit<8> mod;
    state_t stat;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    timestamp_t  timestamp;
    mode_t       md;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MYTMP: parse_mytmp;
            TYPE_MODE: parse_mode;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_mytmp {
        packet.extract(hdr.timestamp);
        transition parse_ipv4;
    }

    state parse_mode {
        packet.extract(hdr.md);
        transition parse_mytmp;
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

    // rule timestamp
    //tmp_t rule_tmp;
    // packet timestamp
    //tmp_t tag_tmp;
    // the index of byte_cnt_reg
    //flowid_t flow_id;
    // count the number of bytes seen since the last probe
    register<state_t>(MAX_FLOWS) pkt_cnt_reg;
    // remember the time of the last probe
    register<time_t>(MAX_FLOWS) last_time_reg;

    //bit<8> mode_bit;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, tmp_t rtmp, tmp_t ttmp, flowid_t flowid) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.timestamp.rtp = rtmp;
        hdr.timestamp.ttp = ttmp;
        hdr.timestamp.fid = flowid;
    }

    action _resubmit(){
        resubmit(meta);
    }

    action set_tmp(){
        hdr.timestamp.ptp = hdr.timestamp.ttp;
        hdr.timestamp.rtp = 0;
        hdr.timestamp.ttp = 0;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action import_state(flowid_t flowid){
        pkt_cnt_reg.read(hdr.md.stat, flowid);
        hdr.md.mod = 1;
    }

    action export_state(flowid_t flowid){
        pkt_cnt_reg.write(flowid, hdr.md.stat);
        standard_metadata.egress_spec = cpu_port;
    }

    table sync_mode {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.md.mod: exact;
        }
        actions = {
            import_state;
            export_state;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action set_flow_count(){
        bit<32> pkt_cnt;
        //bit<32> new_byte_cnt;
        //time_t last_time;
        //time_t cur_time = standard_metadata.ingress_global_timestamp;
        //last_time_reg.read(last_time, flow_id);
        //last_time_reg.write(flow_id, cur_time);
        last_time_reg.write(hdr.timestamp.fid, standard_metadata.ingress_global_timestamp);
        pkt_cnt_reg.read(pkt_cnt, hdr.timestamp.fid);
        //new_byte_cnt = (cur_time > last_time + 1000000) ? 1: (pkt_cnt + 1);
        //byte_cnt_reg.write(flow_id, new_byte_cnt);
        pkt_cnt_reg.write(hdr.timestamp.fid, pkt_cnt+1);
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        // if (hdr.md.isValid()) {
        //     sync_mode.apply();
        // }
        if (hdr.timestamp.isValid() && hdr.timestamp.ptp > hdr.timestamp.rtp){
            _resubmit();
        }
        if (hdr.timestamp.isValid() && hdr.timestamp.ptp <= hdr.timestamp.rtp){
            set_tmp();
            set_flow_count();
        }

        if (hdr.md.isValid()){
            sync_mode.apply();
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
        packet.emit(hdr.timestamp);
        packet.emit(hdr.ipv4);
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
