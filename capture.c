/** Modified from: http://www.aakarshnair.com/posts/berkely-packet-filter **/

#include <stdio.h>
#include <errno.h>
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/filter.h> // <=========

/*

====> sock_filter (VM instruction: 16:8:8:32 (64-bit)
====> sock_fprog  (Number of VM instructions, Array of VM instructions)

struct sock_filter {    // Filter block
        __u16   code;   // Actual filter code
        __u8    jt;     // Jump true
        __u8    jf;     // Jump false
        __u32   k;      // Generic multiuse field
};

*/

struct sock_filter VM_instructions[] = {

{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 15, 0x00000006 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 12, 0, 0x00000017 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x00000017 },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000017 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000017 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },

};

int main()
{
  unsigned char *packet ;
  int saddr_size ;
  int data_size;
  struct sockaddr saddr;         
  int ret;

  const int max_packet_size = 65536;  // 64 KiB
  
  packet  = (unsigned char *) malloc(max_packet_size); 
  
  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;

  if(sock_raw < 0)    {    
    perror("socket(): ");
    exit(1);
  }

  struct sock_fprog fcode;

  fcode.len = sizeof(VM_instructions) / sizeof(struct sock_filter);
  fcode.filter = VM_instructions;
  
  ret = setsockopt(sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &fcode, sizeof(fcode));
  
  if(sock_raw < 0)    {    
    perror("socket(): ");
    exit(2);
  }

  saddr_size = sizeof(saddr);

  printf("sniffing...\n");
  
  while(1) {
    data_size = recvfrom(sock_raw, packet, max_packet_size, 0, &saddr, (socklen_t *)&saddr_size);

    if (data_size < 0) {
      printf("recvfrom(): ");
      exit(3);
    }

    write(0, packet, data_size);
  }
}
