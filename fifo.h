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

#define skb_network_header(skb) ((skb)->head + (skb)->network_header)
#define skb_transport_header(skb) ((skb)->head + (skb)->transport_header)
#define ip_hdr(skb) ((struct iphdr *)skb_network_header(skb))
#define tcp_hdr(skb) ((struct tcphdr *)skb_transport_header(skb))
#define udp_hdr(skb) ((struct udphdr *)skb_transport_header(skb))

static inline void skb_queue_head_init(struct sk_buff_head *list) {
    list->prev = list->next = (struct sk_buff *)list;
    list->qlen = 0;
}

static inline void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk) {

    struct sk_buff *prev = list->prev;
    newsk->next = (struct sk_buff *)list;
    newsk->prev = prev;
    prev->next = newsk;
    list->prev = newsk;
    list->qlen++;

}

static inline struct sk_buff *skb_dequeue(struct sk_buff_head *list) {
    struct sk_buff *skb = list->next;
    if (skb == (struct sk_buff *)list) {
        return NULL;
    }
    struct sk_buff *next = skb->next;
    list->next = next;
    next->prev = (struct sk_buff *)list;
    list->qlen--;
    skb->next = skb->prev = NULL;
    return skb;
}

static inline struct sk_buff *skb_peek(const sk_buff_head *list) {
    struct sk_buff *skb = list->next;
    if (skb == (struct sk_buff *)list) {
        return NULL;
    }
    return skb;
}

static inline void skb_queue_purge(struct sk_buff_head *list) {
    struct sk_buff *skb;
    while ((skb = skb_dequeue(list)) != NULL) {
        // In user-space, free the skb (assuming user manages allocation)
        free(skb->head);  // Free the data buffer
        free(skb);        // Free the skb struct
    }
}

// Simplified Qdisc structure
struct gnet_stats_queue {
    u32 qlen;
};

struct Qdisc {
    struct gnet_stats_queue q;
    // Private data embedded for simplicity in user-space
};



