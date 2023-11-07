/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include "icmp.h"
#include "utilities.h"
#include "ip.h"
#include <stdio.h>
#include "timer.h"
#include <stdlib.h>
#include <string.h>
#include "config.h"

#define ICMP_HEADER_SIZE 8


struct icmp* get_icmp_header(struct subuff *sub, uint32_t* icmp_payload_lenp, struct iphdr** ih, uint32_t* ip_hdr_len){
    struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);
    size_t ip_hdr_len_val = ip_hdr->ihl * 4;
    
    if(icmp_payload_lenp != NULL) *icmp_payload_lenp = ip_hdr->len - ip_hdr_len_val;
    if(ih != NULL) *ih = ip_hdr;
    if(ip_hdr_len != NULL) *ip_hdr_len = ip_hdr_len_val;
    return (struct icmp*) (((uint8_t*) ip_hdr) + ip_hdr_len_val);
}

void icmp_rx(struct subuff *sub)
{
    //FIXME: implement your ICMP packet processing implementation here
    //Hints:
    // Step 1: check if the incoming packet is a valid ICMP packet, does the checksum match?
    // Step 2: what kind of ICMP packet is this? See the
    // Step 3: take appropriate action for ECHO type request, i.e., prepare an ECHO response type (in the icmp_reply function below)
    // Step 4: make sure you do not leak any memory allocated to the sub

    //get ip header to get actual size of ip header
    struct iphdr* ip_hdr;
    uint32_t icmp_payload_len;
    struct icmp* icmp_hdr = get_icmp_header(sub, &icmp_payload_len, &ip_hdr, NULL);
    
    printf("doing checsum ICMP\n");
    if(do_csum(icmp_hdr, icmp_payload_len, 0) != 0){
        printf("Error: ICMP checksum failed droping packet!\n");
        goto drp_pkt;
    }

    printf("checking ICMP packet type\n");
    switch (icmp_hdr->type)
    {

    case ICMP_V4_ECHO:
        printf("ICMP echo request\n");
        icmp_reply(sub);
        break;

    case ICMP_V4_REPLY:
        printf("ICMP reply request\n");
        break;
    
    default:
        printf("Error: unssoprted type of ICMP request received!: %x\n", icmp_hdr->type);
    }

    drp_pkt:
    printf("Freeing ICMP sub\n");
    free_sub(sub);
}

//ask if its ok to change th signature
void icmp_reply(struct subuff *sub)
{
    // FIXME: implement your ICMP reply implementation here
    // Hints:
    // Step 1: prepare an ICMP response buffer
    // Step 2: make sure that all fields are valid, in the network byte order, and the checksum is correct
    // Step 3: send it out on ip_ouput(...)
    // See how ARP processing is implemented for processing and sending packets

    struct iphdr* ip_hdr;
    uint32_t icmp_payload_len;
    uint32_t ip_hdr_len;
    struct icmp* icmp_hdr = get_icmp_header(sub, &icmp_payload_len, &ip_hdr, &ip_hdr_len);
    
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + icmp_payload_len);
    sub_push(sub, icmp_payload_len);

    icmp_hdr->code = htons(0);
    icmp_hdr->type = htons(ICMP_V4_REPLY);
    icmp_hdr->checksum = htons(0);

    icmp_hdr->checksum = do_csum(icmp_hdr, icmp_payload_len, 0);

    if(do_csum(icmp_hdr, icmp_payload_len, 0) != 0){
        printf("invalid checksum\n");
    }

    int res = ip_output(IP_HDR_FROM_SUB(sub)->saddr, sub);
    if(res < 0){
        printf("IP output err code: %d", res);
    }else{
        printf("IP output res: %d", res);
        printf("Sub len %u\n", sub->len);
    }
}
