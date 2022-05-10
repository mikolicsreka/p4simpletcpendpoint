/*
 * Copyright (C) 2017-present,  Netronome Systems, Inc.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <nfp.h>
#include <stdint.h>

#include <nfp/me.h>
#include <blm/blm.h>
#include <nfp/cls.h>
#include <pkt/pkt.h>
#include <std/reg_utils.h>

#include <net/eth.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/csum.h>

#include <nfp/mem_bulk.h>
#include <nfp/mem_atomic.h>

#include <pif_plugin.h>
#include <pif_registers.h>
#include <pif_flcalc.h>

#include "config.h"

/*
 * Defines
 */

#define TCP_DATA_LEN    2
#define WAIT_TIME_NS 5000000000

/* CTM credit defines */
#define MAX_ME_CTM_PKT_CREDITS  256
#define MAX_ME_CTM_BUF_CREDITS  32
#define CTM_ALLOC_ERR 0xffffffff

/* Port mapping macros */
#define MAC_CHAN_PER_PORT   8
#define TMQ_PER_PORT        (MAC_CHAN_PER_PORT * 8)
#define MAC_TO_PORT(x)      (x / MAC_CHAN_PER_PORT)
#define PORT_TO_TMQ(x)      (x * TMQ_PER_PORT)


struct packet_tx_ack {
    union {
        __packed struct {
            uint16_t        eth_dst_hi;
            uint32_t        eth_dst_lo;
            uint16_t        eth_src_hi;
            uint32_t        eth_src_lo;
            uint16_t        eth_type;
            struct ip4_hdr  ip;
            struct tcp_hdr  tcp;
            uint8_t         tcp_data[TCP_DATA_LEN];
        };
        uint16_t            __raw[28];
    };
};


/*
 * Globals
 */

/* Very cheap and nasty debug ring, but rather effective. Note NOT ATOMIC
 * use nfp-rtsym i36._debug to retrieve
 */
volatile __export __mem uint32_t debug[1024 * 16];
volatile __export __mem uint32_t debug_idx = 0;

#define DEBUG(_w, _x, _y,_z) \
    do { \
       debug[debug_idx++] = _w; \
       debug[debug_idx++] = _x; \
       debug[debug_idx++] = _y; \
       debug[debug_idx++] = _z; \
       debug_idx &= 0xffff; \
    } while (0)

/* make sure only half the CTM is used for packet data */
__asm .init_csr xpb:CTMXpbMap.MuPacketReg.MUPEMemConfig 1
__asm .alloc_mem PKT_RSVD ctm+0x0 island 0x20000 reserved

 /* credits for CTM */
__export __shared __cls struct ctm_pkt_credits ctm_credits_2 =
           {MAX_ME_CTM_PKT_CREDITS, MAX_ME_CTM_BUF_CREDITS};

/* counters for out of credit situations */
volatile __export __mem uint64_t gen_pkt_ctm_wait;
volatile __export __mem uint64_t gen_pkt_blm_wait;


/*
 * Packet data operations
 */

static void build_tx_ack(EXTRACTED_HEADERS_T *headers, __lmem struct packet_tx_ack *Pdata)
{
    uint8_t i;
    uint8_t payload_size = pif_plugin_meta_get__standard_metadata__packet_length(headers) - 54 - 12; //Eth,IPv4,TCP == 54 bytes
    PIF_PLUGIN_ethernet_T *eth_hdr = pif_plugin_hdr_get_ethernet(headers);

    reg_zero(Pdata->__raw, sizeof(struct packet_tx_ack));
    
    Pdata->eth_dst_hi = PIF_HEADER_GET_ethernet___srcAddr___1(pif_plugin_hdr_get_ethernet(headers));
    Pdata->eth_dst_lo = PIF_HEADER_GET_ethernet___srcAddr___0(pif_plugin_hdr_get_ethernet(headers));
    Pdata->eth_src_hi = PIF_HEADER_GET_ethernet___dstAddr___1(pif_plugin_hdr_get_ethernet(headers));
    Pdata->eth_src_lo = PIF_HEADER_GET_ethernet___dstAddr___0(pif_plugin_hdr_get_ethernet(headers));
    Pdata->eth_type = NET_ETH_TYPE_IPV4;

    Pdata->ip.ver = 4;
    Pdata->ip.hl = 5;
    Pdata->ip.tos = 0;
    Pdata->ip.len = sizeof(Pdata->ip) +
                    sizeof(Pdata->tcp);
    Pdata->ip.id = PIF_HEADER_GET_port_register___value(&pif_register_port_register[1]) + 1;
    Pdata->ip.frag = 0x4000;
    Pdata->ip.ttl = 64;
    Pdata->ip.proto = 6;
    Pdata->ip.sum = 0; 
    Pdata->ip.src = PIF_HEADER_GET_ipv4___dstAddr(pif_plugin_hdr_get_ipv4(headers));
    Pdata->ip.dst = PIF_HEADER_GET_ipv4___srcAddr(pif_plugin_hdr_get_ipv4(headers));

    Pdata->tcp.sport = PIF_HEADER_GET_tcp___dstPort(pif_plugin_hdr_get_tcp(headers));
    Pdata->tcp.dport = PIF_HEADER_GET_tcp___srcPort(pif_plugin_hdr_get_tcp(headers));
    Pdata->tcp.seq = PIF_HEADER_GET_tcp___ackNo(pif_plugin_hdr_get_tcp(headers));
    Pdata->tcp.ack = pif_register_upstream_states_register[0].value;
    Pdata->tcp.off = 5;
    Pdata->tcp.flags = NET_TCP_FLAG_ACK;
    Pdata->tcp.win = 7240;
    Pdata->tcp.sum = 0;
    Pdata->tcp.urp = 0;
}

/*
 * Packet metadata operations
 */

static void build_tx_meta(__lmem struct nbi_meta_catamaran *nbi_meta)
{
    __xread blm_buf_handle_t buf;
    int pkt_num;
    int blq = 0;

    reg_zero(nbi_meta->__raw, sizeof(struct nbi_meta_catamaran));

    /*
     * Poll for a CTM buffer until one is returned
     */
    while (1) {
        pkt_num = pkt_ctm_alloc(&ctm_credits_2, __ISLAND, PKT_CTM_SIZE_256, 1, 0);
        if (pkt_num != CTM_ALLOC_ERR)
            break;
        sleep(1000);
        mem_incr64((__mem void *) gen_pkt_ctm_wait);
    }
    /*
     * Poll for MU buffer until one is returned.
     */
    while (blm_buf_alloc(&buf, blq) != 0) {
        sleep(1000);
        mem_incr64((__mem void *) gen_pkt_blm_wait);
    }

    nbi_meta->pkt_info.isl = __ISLAND;
    nbi_meta->pkt_info.pnum = pkt_num;
    nbi_meta->pkt_info.bls = blq;
    nbi_meta->pkt_info.muptr = buf;

    /* all other fields in the nbi_meta struct are left zero */
}

/*
 * Init
 */

static void init_me()
{
    local_csr_write(local_csr_mailbox0, 0);
    local_csr_write(local_csr_mailbox1, 0);
    local_csr_write(local_csr_mailbox2, 0);
    local_csr_write(local_csr_mailbox3, 0);
}

/*
 * Main
 */

int pif_plugin_send_ack(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data){
    __lmem struct nbi_meta_catamaran mdata;
    volatile __lmem struct packet_tx_ack pdata;
    __gpr struct pkt_ms_info msi;
    __xwrite uint32_t xwr[32];
    __mem char *pbuf;
    
    volatile void *ip_ptr, *tcp_ptr;
    volatile __mem40 void *tcp_start_ptr;
    int pkt_offset = PKT_NBI_OFFSET;
    int pkt_len = sizeof(struct packet_tx_ack);
    int meta_len = sizeof(struct nbi_meta_catamaran);
    uint32_t out_port;
    init_me();

    /* Allocate packet and write out packet metadata to packet buffer */
    build_tx_meta(&mdata);
    reg_cp((void*)xwr, (void*)&mdata, meta_len);
    pbuf = pkt_ctm_ptr40(mdata.pkt_info.isl, mdata.pkt_info.pnum, 0);
    mem_write32(xwr, pbuf, meta_len);
    
    build_tx_ack(headers, &pdata);

    ip_ptr = (void*)&pdata.ip;
    tcp_start_ptr = (__mem40 void*)&pdata.tcp.sport;
    
    pdata.ip.sum = net_csum_ipv4(ip_ptr, tcp_start_ptr);

    tcp_ptr = (void*)&pdata.tcp;

    /* calculate TCP checksum */
    pdata.tcp.sum = net_csum_ipv4_tcp(ip_ptr, tcp_ptr, tcp_start_ptr, 0, (void*)&pdata.tcp, 20);
    /* copy and write out the packet data into the packet buffer */
    reg_cp((void*)xwr, (void*)pdata.__raw, pkt_len);
    mem_write32(xwr, pbuf + pkt_offset, pkt_len);

    
    
    /* set up the packet modifier to trim bytes for alignment */
    msi = pkt_msd_write(pbuf, PKT_NBI_OFFSET);
    pkt_mac_egress_cmd_write(pbuf, PKT_NBI_OFFSET, 1, 1);

    /* send the packet */
    out_port = pif_plugin_meta_get__standard_metadata__ingress_port(headers);
    pkt_nbi_send(mdata.pkt_info.isl, mdata.pkt_info.pnum, &msi,
                 pkt_len,
                 0, //nbi = 0 
                 PORT_TO_TMQ(out_port), //client on port 1
                 mdata.seqr, mdata.seq, PKT_CTM_SIZE_256);

    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_recalc_checksum(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data){
    uint16_t oldCsum;
    uint32_t newSeqAckNo, oldSeqAckNo = pif_plugin_meta_get__scalars__metadata__old_seq_ack_no(headers);
    uint32_t newTsval, oldTsval = pif_plugin_meta_get__scalars__metadata__old_tsval(headers);
    uint32_t newTsecr, oldTsecr = pif_plugin_meta_get__scalars__metadata__old_tsecr(headers);

    if(PIF_HEADER_GET_tcp___ctrl(pif_plugin_hdr_get_tcp(headers)) == 0x18) {
        newSeqAckNo = PIF_HEADER_GET_tcp___seqNo(pif_plugin_hdr_get_tcp(headers));
    } else if(PIF_HEADER_GET_tcp___ctrl(pif_plugin_hdr_get_tcp(headers)) == 0x10){
        newSeqAckNo = PIF_HEADER_GET_tcp___ackNo(pif_plugin_hdr_get_tcp(headers));
    } 
    newTsval = PIF_HEADER_GET_tcp___options_tsval(pif_plugin_hdr_get_tcp(headers));
    newTsecr = PIF_HEADER_GET_tcp___options_tsecr(pif_plugin_hdr_get_tcp(headers));
    
    oldCsum = PIF_HEADER_GET_tcp___checksum(pif_plugin_hdr_get_tcp(headers));

    if(oldSeqAckNo != newSeqAckNo) {
        oldCsum = ~(~oldCsum + ~oldSeqAckNo + newSeqAckNo) - 1;
    }

    if(oldTsval != newTsval) {
        oldCsum = ~(~oldCsum + ~oldTsval + newTsval) - 1;
    } 

    if(oldTsecr != newTsecr) {
        oldCsum = ~(~oldCsum + ~oldTsecr + newTsecr) - 1;
    }
    
    PIF_HEADER_SET_tcp___checksum(pif_plugin_hdr_get_tcp(headers), oldCsum);
    return PIF_PLUGIN_RETURN_FORWARD;
}

