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
#include "systems_headers.h"

#define ICMP_HEADER_SIZE 8

struct icmp* get_icmp_header(struct subuff *sub){
    struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);
    return (struct icmp*) (((uint8_t*) ip_hdr) + IP_HDR_LEN);
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
    struct icmp* icmp_hdr = get_icmp_header(sub);
    
    if(do_csum(icmp_hdr, IP_PAYLOAD_LEN(IP_HDR_FROM_SUB(sub)), 0) != 0){
        printf("Error: ICMP checksum failed droping packet!\n");
        goto drp_pkt;
    }

    switch (icmp_hdr->type)
    {

    case ICMP_V4_ECHO:
        printf("ICMP echo request\n");
        return icmp_reply(sub);

    case ICMP_V4_REPLY:
        printf("ICMP reply request\n");
    
    default:
        printf("Error: unssoprted type of ICMP request received!: %x\n", icmp_hdr->type);
    }

    drp_pkt:
    free_sub(sub);
}

struct icmp_reply_attempt_args{
    uint32_t dest_addr;
    struct subuff *sub;
    uint8_t attemptc;
};

void* icmp_reply_attempt(void* args){
    struct icmp_reply_attempt_args* actual_args = (struct icmp_reply_attempt_args*) args;

    struct subuff* sub = actual_args->sub;
    int succesful = 0;
    for(uint8_t i = 0; i < actual_args->attemptc; i++){
        if(ip_output(actual_args->dest_addr, sub) == sub->len){
            succesful = 1;
            break;
        }

        sub_pop(sub, IP_HDR_LEN);
        sleep(0.1);
    }

    if(!succesful) debug_ip_hdr("Failed to send ICMP reply!", IP_HDR_FROM_SUB(sub));

    free_sub(sub);
    return NULL;
}

void icmp_reply(struct subuff *sub)
{
    // FIXME: implement your ICMP reply implementation here
    // Hints:
    // Step 1: prepare an ICMP response buffer
    // Step 2: make sure that all fields are valid, in the network byte order, and the checksum is correct
    // Step 3: send it out on ip_ouput(...)
    // See how ARP processing is implemented for processing and sending packets

    struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);
    uint32_t icmp_packet_len = IP_PAYLOAD_LEN(ip_hdr);
    struct icmp* icmp_hdr = get_icmp_header(sub);
    
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + icmp_packet_len);
    sub_push(sub, icmp_packet_len);

    icmp_hdr->code = htons(0);
    icmp_hdr->type = htons(ICMP_V4_REPLY);
    icmp_hdr->checksum = htons(0);

    icmp_hdr->checksum = do_csum(icmp_hdr, icmp_packet_len, 0);

    if(do_csum(icmp_hdr, icmp_packet_len, 0) != 0) debug_ip_hdr("Invalid ICMP checksum\n", ip_hdr);
    
    sub->protocol = 1;
    
    struct icmp_reply_attempt_args args;
    args.attemptc = 10;
    args.dest_addr = ip_hdr->saddr;
    args.sub = alloc_sub(ANP_MTU_15_MAX_SIZE);
    memcpy(args.sub, sub, ANP_MTU_15_MAX_SIZE);

    pthread_t tid;
    pthread_create(&tid, NULL, icmp_reply_attempt, &args);
}
