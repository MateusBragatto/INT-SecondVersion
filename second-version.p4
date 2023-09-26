/* -*- P4_16 -*- */

/*
Compilar:
sudo p4c -b bmv2 second-version.p4 -o second-version.bmv2
Rodar switch:
sudo simple_switch --device-id 1 --thrift-port 9090 --interface 0@enp0s8 --interface 1@enp0s9 second-version.bmv2/second-version.json -- --priority-queues 8
Atualizar tabelas:
sudo cat second-version-table1.txt | simple_switch_CLI
*/


#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

#define MAX_HOPS 10


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;
typedef bit<9> egressSpec_v;

typedef bit<8> switchID_v;
typedef bit<32> enq_qdepth_v;
typedef bit<3> priority_v;
typedef bit<5> qid_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
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
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}

header nodeCount_h{
    bit<16>  count;
    bit<16> priority;
}

header InBandNetworkTelemetry_h {
    switchID_v swid;
    priority_v priority;
    qid_v qid;
    //n variables for n registers. both with 32 bits (register with 32 bits)
    enq_qdepth_v enq_qdepth0;
    enq_qdepth_v enq_qdepth1;
    bit<16> totalLen;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
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
            IP_PROTO: parse_count;
            default: accept;
        }
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
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
    
    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            //standard_metadata.priority = 5;
            standard_metadata.priority = (priority_v) hdr.nodeCount.priority;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    //register<enq_qdepth_v>(2) reg_qdepth;
    register<enq_qdepth_v>(1) reg_qdepth_0;
    register<enq_qdepth_v>(1) reg_qdepth_1;

    action r_register_manipulation_0(){
        //lendo o registrador 0 na posicao 0 (so tem essa) e armazenado no qdepth0 do int
        //enq_qdepth_v = 19
        bit<32> qdepth_value;
        reg_qdepth_0.read(qdepth_value,0);
        hdr.INT[0].enq_qdepth0 = qdepth_value;
    }

    action r_register_manipulation_1(){
        //lendo o registrador 1 na posicao 0 (so tem essa) e armazenado no qdepth1 do int
        //enq_qdepth_v = 19bit
        bit<32> qdepth_value;
        reg_qdepth_1.read(qdepth_value,0);
        hdr.INT[0].enq_qdepth1 = qdepth_value;
    }

    action w_register_manipulation_0(){
        //register 0, qid 0
        //enq_qdepth_v = 19
        //standar_metadata_qdepth tbm eh 19 bits

        reg_qdepth_0.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
        
    }

    action w_register_manipulation_1(){
        //register 1, qid 1
        reg_qdepth_1.write(0, (enq_qdepth_v) standard_metadata.enq_qdepth);
        
    }

    action add_swtrace(switchID_v swid) { 
        //ler numa variavel temporaria que estava no egress, n ler agora do metadata
        //pra emxer so uma vez no registrador, manter sincroniza;ao das variaveis do bloco egresso com o resgistrador
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].priority = (priority_v)standard_metadata.priority;
        hdr.INT[0].qid = (qid_v)standard_metadata.qid;
        //8 bits (swid) + 5 (priority) + 3(qid) + 32(qdepth0) + 32(qdepth1) = 80bits = 10 bytes
        // + 2 bytes totalLen
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;//12
        hdr.INT[0].totalLen = (bit<16>) hdr.ipv4.totalLen;
    }

    table read_register_manipulation_0{
        actions = {
            r_register_manipulation_0;
            NoAction;
        }
        default_action = NoAction();
    }

    table read_register_manipulation_1{
        actions = {
            r_register_manipulation_1;
            NoAction;
        }
        default_action = NoAction();
    }

    table write_register_manipulation_0{
        actions = {
            w_register_manipulation_0;
            NoAction;
        }
        default_action = NoAction();
    }

    table write_register_manipulation_1{
        actions = {
            w_register_manipulation_1;
            NoAction;
        }
        default_action = NoAction();
    }

    table swtrace {
        actions = { 
	        add_swtrace; 
	        NoAction; 
        }
        default_action = NoAction();
    }
    
    apply {
        //se for um pacote com int, fazer a leitura dos valores que estao nos registradores
        if (hdr.nodeCount.isValid()) {
            swtrace.apply();
            read_register_manipulation_0.apply();//second-version, leituras
            read_register_manipulation_1.apply();
        }
        else{
            //apenas armazenar o da sua propria qdepth se for um pacote comum
            if(standard_metadata.qid == 0){
                write_register_manipulation_0.apply();
            }
            else if(standard_metadata.qid == 1){
                write_register_manipulation_1.apply();
            }
        }
    }  
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
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);                 
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