/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

// clang -O2 -Wall -c droppacket.c -o dropjit.o
// 
// For bpf code: clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o
// this passes the checker


#include "ebpf.h"

#pragma clang section data="maps"
struct bpf_map_def port_map = {
      .type        = 2,
      .key_size    = sizeof(__u32),
      .value_size  = sizeof(__u32),
      .max_entries = 1,
      .map_flags   = 0
};

#pragma clang section text="xdp"
int DropPacket(xdp_md* ctx)
{
      IPV4_HEADER* iphdr = (IPV4_HEADER*)ctx->data;
      UDP_HEADER* udphdr = (UDP_HEADER*)(iphdr + 1);
      int rc = 1;
      if ((char *)ctx->data + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) > (char *)ctx->data_end)
           goto Done;

      // udp
      if (iphdr->Protocol == 17)
      {
          if (ntohs(udphdr->length) <= sizeof(UDP_HEADER))
          {
              long key = 0;
              long* count = ebpf_map_lookup_elem(&port_map, &key);
              if (count) 
                  *count = (*count + 1);
              rc = 2;
          }
      }
Done:
      return rc;     
}