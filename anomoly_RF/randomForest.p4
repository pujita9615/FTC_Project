#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
#define CLASS_NOT_SET 10000 // A big number

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
struct learn_t {
    bit<16> digest;
}

struct metadata {
     bit<16> class;
     bit<16> prevFeature;
     bit<16> node_id;
     bit<16> isTrue;
    learn_t learn;

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t      tcp;
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
            default: accept;
        }
    }

   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
    }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    action drop() {
            mark_to_drop(standard_metadata);
        }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {


            standard_metadata.egress_spec = port;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = dstAddr;
        }
// Setting the classification
    action SetClass(bit<16> node_id, bit<16> class){
        meta.class = class;
    }


    action CheckFeature(bit<16> node_id, bit<16> feat, bit<16> threshold){
        bit<16> feature = 0;
        bit<16> th = threshold;
		bit<16> f = feat + 1;

        if (feat == 0){
            feature =(bit<16>) hdr.ipv4.flags;
        }

        if (feat == 1){
            feature = (bit<16>)hdr.ipv4.ttl;
        }

        if (feat == 2){
            feature = (bit<16>)hdr.tcp.seqNo;
        }
        if(feat == 3){
            feature = (bit<16>)hdr.tcp.ackNo;
        }

        if (feature <= th) meta.isTrue = 1;
        	else meta.isTrue = 0;

        	meta.prevFeature = f - 1;

        	meta.node_id = node_id;

    }

action class_init(){
        meta.class = 2;
        meta.isTrue = 1 ;
    }

// Table 1
    table level1 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size = 1024;
    }
// Table 2
    table level2 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size = 1024;
    }

// Table 3
    table level3 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size =1024;
    }


// Table 4
    table level4 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size =1024;
    }


// Table 5
    table level5 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size =1024;
    }

// Table 6
    table level6 {
        key = {
            meta.node_id: exact;
            meta.prevFeature: exact;
            meta.isTrue: exact;
        }
        actions = {
            NoAction;
            CheckFeature;
            SetClass;
        }
        size =1024;
    }

    // Table 7
      table level7 {
          key = {
                meta.node_id: exact;
                meta.prevFeature: exact;
                meta.isTrue: exact;
            }
            actions = {
                NoAction;
                CheckFeature;
                SetClass;
            }
            size =1024;
        }

        // Table 8
            table level8 {
                key = {
                    meta.node_id: exact;
                    meta.prevFeature: exact;
                    meta.isTrue: exact;
                }
                actions = {
                    NoAction;
                    CheckFeature;
                    SetClass;
                }
                size =1024;
            }

            // Table 9
                table level9 {
                    key = {
                        meta.node_id: exact;
                        meta.prevFeature: exact;
                        meta.isTrue: exact;
                    }
                    actions = {
                        NoAction;
                        CheckFeature;
                        SetClass;
                    }
                    size =1024;
                }

                // Table 10
                    table level10{
                        key = {
                            meta.node_id: exact;
                            meta.prevFeature: exact;
                            meta.isTrue: exact;
                        }
                        actions = {
                            NoAction;
                            CheckFeature;
                            SetClass;
                        }
                        size =1024;
                    }

    table ipv4_exact {
            key = {
                meta.class: exact;
    	}
            actions = {
                ipv4_forward;
                drop;
                NoAction;
            }
            size = 1024;
            default_action = drop();
        }


apply{
		class_init();

    if ( hdr.ipv4.isValid()) {
         if (hdr.ipv4.protocol == 6 ) {

            if (meta.class == CLASS_NOT_SET) {
        		  level1.apply();
        		  if (meta.class == CLASS_NOT_SET) {
        		    level2.apply();
        		    if (meta.class == CLASS_NOT_SET) {
        			level3.apply();
        			if (meta.class == CLASS_NOT_SET) {
        			  level4.apply();
        			  if (meta.class == CLASS_NOT_SET) {
        			    level5.apply();
        			    if (meta.class == CLASS_NOT_SET) {
        			      level6.apply();
                    if (meta.class == CLASS_NOT_SET) {
                      level7.apply();
                      if (meta.class == CLASS_NOT_SET) {
                        level8.apply();
                        if (meta.class == CLASS_NOT_SET) {
                          level9.apply();
                          if (meta.class == CLASS_NOT_SET) {
                            level10.apply();

                      }}}}}}}}}}

                  }

            meta.learn.digest = meta.class;

           //digest packet
            digest(1, meta.learn);
                 ipv4_exact.apply();

              }


    }  // end of apply

} // end of MyIngress

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.tcp);
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
