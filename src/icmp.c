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


struct icmp* get_icmp_header(struct subuff *sub, uint32_t* icmp_payload_lenp, struct iphdr** ih){
    struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    
    if(icmp_payload_lenp != NULL) *icmp_payload_lenp = ip_hdr->len - ip_hdr_len;
    if(ih != NULL) *ih = ip_hdr;
    return (struct icmp*) (((uint8_t*) ip_hdr) + ip_hdr_len);
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
    struct icmp* icmp_hdr = get_icmp_header(sub, &icmp_payload_len, &ip_hdr);

    if(do_csum(icmp_hdr, icmp_payload_len, 0) != 0){
        printf("Error: ICMP checksum failed droping packet!\n");
        goto drp_pkt;
    }

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
        printf("Error: unssoprted type of ICMP request received!");
    }

    drp_pkt:
    free_sub(sub);
    assert(false);
}

struct ip_send_args{
    uint32_t dest_addr;
    struct subuff *sub;
};

void send_ip(void* args){
    struct ip_send_args* is_args = (struct ip_send_args*) args;
    int res;
    do{
        usleep(100000);
        res = ip_output(is_args->dest_addr, is_args->sub);
    }while (res != 0);
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
    struct icmp* icmp_hdr = get_icmp_header(sub, &icmp_payload_len, &ip_hdr);

    sub_push(sub, icmp_payload_len);
    icmp_hdr->type = ICMP_V4_REPLY;
    icmp_hdr->checksum = do_csum(icmp_hdr, icmp_payload_len, 0);

    //schedule ip_output() after 5 seconds quit trying
    struct ip_send_args args;
    args.dest_addr = ip_hdr->saddr;
    args.sub = sub;
    timer_add(5000, send_ip, (void*) &args);
}
