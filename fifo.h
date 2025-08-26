#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

static u16 flow1_src_port = 0;
static u16 flow2_src_port = 0;

// Simplified definitions for sk_buff and related structures
struct sk_buff;

struct sk_buff_head {
    struct sk_buff *next;
    struct sk_buff *prev;
    u32 qlen;
};

struct sk_buff {
    struct sk_buff *next;
    struct sk_buff *prev;
    unsigned char *head;  // Start of the allocated buffer
    unsigned char *data;  // Current data pointer
    unsigned int len;     // Length of data in the skb
    u16 network_header;   // Offset to network header
    u16 transport_header; // Offset to transport header
};
