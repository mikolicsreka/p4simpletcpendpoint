/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<1> is_connection_established;
    //bit<32> seqDiff;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
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
       transition select(hdr.ipv4.protocol){
           TYPE_TCP: tcp;
           default: accept;
       }
   }

   state tcp {
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


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    //For packets coming after connection establishment	
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_syn;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_conn;
    bit<32> reg_pos_syn; bit<1> reg_val_syn;
    bit<32> reg_pos_conn; bit<1> reg_val_conn;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr1, bit<16> port1){
       hash(reg_pos_syn, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                       port1,
                                                       hdr.ipv4.protocol},
                                                       (bit<32>)BLOOM_FILTER_ENTRIES);
       hash(reg_pos_conn, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                       port1,
                                                       hdr.ipv4.protocol},
                                                       (bit<32>)BLOOM_FILTER_ENTRIES);
    }
    action send_back() {
        /* Back to the sender */
        bit<48> tmp;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp; /*ahonnan most kuldjuk az lesz az uj src*/
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action create_ack_response() {
        /* Back to the sender */
	bit<48> tmp;
	tmp = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = hdr.ethernet.srcAddr; 
	hdr.ethernet.srcAddr = tmp; /*ahonnan most kuldjuk az lesz az uj src*/
	standard_metadata.egress_spec = standard_metadata.ingress_port;
   	hdr.ipv4.ttl = hdr.ipv4.ttl - 1; /*ne bolyongjon vegtleen ideig*/

	//Set the TCP Flags:
	hdr.tcp.syn = 0;
	hdr.tcp.ack = 1;
	
	//Set the seq.no
	bit <32> seq = hdr.tcp.seqNo;
	hdr.tcp.seqNo = hdr.tcp.ackNo;
	hdr.tcp.ackNo = seq + 1;
    }

    action create_syn_ack_response() {
        /* Back to the sender */
        bit<48> tmp;
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp; /*ahonnan most kuldjuk az lesz az uj src*/
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1; /*ne bolyongjon vegtleen ideig*/

        //Set the TCP Flags:
        hdr.tcp.syn = 1;
        hdr.tcp.ack = 1;

        //Set the seq.no
        bit <32> seq = hdr.tcp.seqNo;
        hdr.tcp.seqNo = hdr.tcp.ackNo;
        hdr.tcp.ackNo = seq + 1;
    }
    
    apply {
	if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
		//Compute connection hash to see that the TCP connection
		// is already established.
		compute_hashes(hdr.ipv4.srcAddr, hdr.tcp.srcPort);
		bloom_filter_conn.read(reg_val_conn, reg_pos_conn);
		if(reg_val_conn == 1)
		{
			meta.is_connection_established = 1;
		} else
		{
			meta.is_connection_established = 0;
		}
		
	        //check if the connection is established to forward, otherwise discard
                if (meta.is_connection_established == 1){
                      //sequence and acknowledgment numbers should be adapted to the new connection
                      create_ack_response();
                } else
		{
			if(hdr.tcp.syn == 1 && hdr.tcp.ack == 0){
				//Megjott az elso SYN packet -> beletesszuk a syn bloomfiltebe
				bloom_filter_syn.write(reg_pos_syn, 1);
				create_syn_ack_response();	
			} else if(hdr.tcp.syn == 0 && hdr.tcp.ack == 1) {
				//1. Volt mar syn?
				bloom_filter_syn.read(reg_val_syn, reg_pos_syn);
				if(reg_val_syn == 1){
				//Ha igen: conn establish
					bloom_filter_conn.write(reg_pos_conn, 1);
					create_ack_response();
				} else
				{ //Ha nem: drop
					drop();
				}
			} else if(hdr.tcp.fin == 1) {
			    	create_syn_ack_response();
				// Change values to 0 -> closed
				bloom_filter_syn.write(reg_pos_syn, 0);
				bloom_filter_conn.write(reg_pos_conn, 0);
			}
			else {
				drop();
			}
		}
		
	}
	if (hdr.ipv4.isValid()) { //Sima IP packetet visszakuldjuk
		send_back();
	} 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
