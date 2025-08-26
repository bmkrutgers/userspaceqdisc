# userspaceqdisc
Porting the fifo qdisc to user space program

identified mappings :


Datstructures:

1) sk_buff : network packet

we will be porting the required parts of sk_buff defined kernel:

struct sk_buff {
    struct sk_buff *next;         // Next packet in the queue
    struct sk_buff *prev;         // Previous packet in the queue
    unsigned char *head;          // Start of the allocated buffer
    unsigned char *data;          // Current data pointer
    unsigned int len;             // Length of data in the skb
    u16 network_header;           // Offset to network header (IP)
    u16 transport_header;         // Offset to transport header (TCP/UDP)
}

2) sk_buff_head:

   Represents a doubly-linked list for queuing sk_buff packets.
struct sk_buff_head {
    struct sk_buff *next;         // Pointer to the first packet
    struct sk_buff *prev;         // Pointer to the last packet
    u32 qlen;                     // Number of packets in the queue
}


3) gnet_stats_queue 
Tracks queue stats , here only queue length is the only need stat
struct gnet_stats_queue {
    u32 qlen;                     // Current queue length
}

4) Qdisc
   It represents user space qdisc
   struct Qdisc {
    struct gnet_stats_queue q;    // Queue statistics (qlen)
}

5) myfifo_sched_data

   qdisc structure that holds all the data

   struct myfifo_sched_data {
    struct sk_buff_head q;        // Single queue for all packets
    u16 flow1_src_port;           // Source port for Flow A
    u16 flow2_src_port;           // Source port for Flow B
    u32 seq_a;                    // Sequence counter for Flow A
    u32 seq_b;                    // Sequence counter for Flow B
    u32 seq_c;                    // Sequence counter for Flow C (others)
}

Function Calls:

packet related:

1) skb_queue_head_init(struct sk_buff_head *list)

 Purpose: Initializes an empty queue (sets next/prev to self, qlen=0).

2) skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)

Purpose: Adds a packet to the tail of the queue and increments queue length

3) skb_dequeue(struct sk_buff_head *list)

Purpose: Removes and returns the head packet, decrement queue length 

4) skb_peek(struct sk_buff_head *list)

Purpose: Returns the head packet without removing it, returns NULL if there are no packets 

5) skb_queue_purge(struct sk_buff_head *list)

Purpose: Removes and frees all packets in the queue. Resets the queue structure

Qdisc related:

1) myfifo_init(struct Qdisc *sch)

Purpose: Initializes the qdisc, setting up the queue, flow ports, and sequence counters

2) myfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch)

Purpose: Enqueues a packet, classifies it into Flow A, B, or C based on source port, logs the event, and updates queue length 

3) myfifo_dequeue(struct Qdisc *sch)

Purpose: Dequeues a packet, logs the event, updates qlen, and increments the appropriate sequence counter.

4) myfifo_peek(struct Qdisc *sch)

Purpose: Peeks at the head packet without dequeuing

5) myfifo_reset(struct Qdisc *sch)

Purpose: Resets the queue and counters (qlen, seq_a, seq_b, seq_c).

6) myfifo_destroy(struct Qdisc *sch)

Purpose: Cleans up the qdisc by resetting the queue



