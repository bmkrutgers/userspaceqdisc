#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/netlink.h>
#include <linux/moduleparam.h>

static u16 flow1_src_port = 0;
static u16 flow2_src_port = 0;
module_param(flow1_src_port, ushort, 0644);
MODULE_PARM_DESC(flow1_src_port, "Source port for flow 1");
module_param(flow2_src_port, ushort, 0644);
MODULE_PARM_DESC(flow2_src_port, "Source port for flow 2");

/* Define attributes for custom qdisc options */
enum {
    MYFIFO_ATTR_UNSPEC,
    MYFIFO_ATTR_FLOW1_SRC_PORT,
    MYFIFO_ATTR_FLOW2_SRC_PORT,
    __MYFIFO_ATTR_MAX,
};
#define MYFIFO_ATTR_MAX (__MYFIFO_ATTR_MAX - 1)

/* Private data for our qdisc */
struct myfifo_sched_data {
    struct sk_buff_head q;         /* Single queue for all packets */
    u16 flow1_src_port;            /* Flow A source port */
    u16 flow2_src_port;            /* Flow B source port */
    u32 seq_a;                     /* Sequence counter for Flow A */
    u32 seq_b;                     /* Sequence counter for Flow B */
    u32 seq_c;                     /* Sequence counter for Flow C (others) */
};

/* Initialize the qdisc */
static int myfifo_init(struct Qdisc *sch, struct nlattr *opt,
                       struct netlink_ext_ack *extack)
{
    struct myfifo_sched_data *q = qdisc_priv(sch);
    skb_queue_head_init(&q->q);
    q->flow1_src_port = flow1_src_port;
    q->flow2_src_port = flow2_src_port;
    q->seq_a = 0;
    q->seq_b = 0;
    q->seq_c = 0;

    if (opt) {
        struct nlattr *tb[MYFIFO_ATTR_MAX + 1];
        int err = nla_parse(tb, MYFIFO_ATTR_MAX, opt, nla_len(opt), NULL, extack);
        if (err) return err;
        if (tb[MYFIFO_ATTR_FLOW1_SRC_PORT])
            q->flow1_src_port = nla_get_u16(tb[MYFIFO_ATTR_FLOW1_SRC_PORT]);
        if (tb[MYFIFO_ATTR_FLOW2_SRC_PORT])
            q->flow2_src_port = nla_get_u16(tb[MYFIFO_ATTR_FLOW2_SRC_PORT]);
    }

    printk(KERN_INFO "myfifo: Initialized with flow1_src_port=%u, flow2_src_port=%u\n",
           q->flow1_src_port, q->flow2_src_port);
    return 0;
}

/* Enqueue: Simply append skb to the queue */
static int myfifo_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
    struct myfifo_sched_data *q = qdisc_priv(sch);
    struct iphdr *iph = ip_hdr(skb);
    unsigned int payload_len = 0;
    u16 src_port = 0;
    u64 now = ktime_get_ns();

    // Calculate payload length and source port
    if (iph && (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = tcp_hdr(skb);
            src_port = ntohs(tcph->source);
            payload_len = skb->len - (iph->ihl * 4) - (tcph->doff * 4);
        } else {
            struct udphdr *uh = udp_hdr(skb);
            src_port = ntohs(uh->source);
            payload_len = skb->len - (iph->ihl * 4) - sizeof(struct udphdr);
        }
    } else {
        payload_len = skb->len; // Non-TCP/UDP: assume full length
    }

    // Log enqueue event
    if (src_port == q->flow1_src_port) {
        q->seq_a++;
        printk(KERN_INFO "[FIFO] A E %llu %u %u %u\n",
               now, payload_len, q->seq_a, sch->q.qlen);
    } else if (src_port == q->flow2_src_port) {
        q->seq_b++;
        printk(KERN_INFO "[FIFO] B E %llu %u %u %u\n",
               now, payload_len, q->seq_b, sch->q.qlen);
    } else {
        q->seq_c++;
        printk(KERN_INFO "[FIFO] C E %llu %u %u %u\n",
               now, payload_len, q->seq_c, sch->q.qlen);
    }

    skb_queue_tail(&q->q, skb);
    sch->q.qlen++;
    return NET_XMIT_SUCCESS;
}

/* Dequeue: Remove skb and log in the specified format with [FIFO] prefix */
static struct sk_buff *myfifo_dequeue(struct Qdisc *sch)
{
    struct myfifo_sched_data *q = qdisc_priv(sch);
    struct sk_buff *skb = skb_dequeue(&q->q);

    if (skb) {
        u64 now = ktime_get_ns();
        struct iphdr *iph = ip_hdr(skb);
        unsigned int payload_len = 0;  // To store the payload length
        sch->q.qlen--;

        if (iph && (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)) {
            u16 src_port = iph->protocol == IPPROTO_TCP ?
                           ntohs(tcp_hdr(skb)->source) : ntohs(udp_hdr(skb)->source);

            // Calculate payload length by removing IP and transport headers
            if (iph->protocol == IPPROTO_UDP) {
                payload_len = skb->len - (iph->ihl * 4) - sizeof(struct udphdr);
            } else if (iph->protocol == IPPROTO_TCP) {
                struct tcphdr *tcph = tcp_hdr(skb);
                payload_len = skb->len - (iph->ihl * 4) - (tcph->doff * 4);
            }

            if (src_port == q->flow1_src_port) {
                q->seq_a++;
                printk(KERN_INFO "[FIFO] A %llu %u %u %u\n",
                       now, payload_len, q->seq_a, sch->q.qlen);
            } else if (src_port == q->flow2_src_port) {
                q->seq_b++;
                printk(KERN_INFO "[FIFO] B %llu %u %u %u\n",
                       now, payload_len, q->seq_b, sch->q.qlen);
            } else {
                q->seq_c++;
                printk(KERN_INFO "[FIFO] C %llu %u %u %u\n",
                       now, payload_len, q->seq_c, sch->q.qlen);
            }
        } else {
            /* Non-TCP/UDP packets: assume entire skb->len is payload (simplified) */
            payload_len = skb->len;
            q->seq_c++;
            printk(KERN_INFO "[FIFO] C %llu %u %u %u\n",
                   now, payload_len, q->seq_c, sch->q.qlen);
        }
    }
    return skb;
}

/* Peek at the head of the queue */
static struct sk_buff *myfifo_peek(struct Qdisc *sch)
{
    struct myfifo_sched_data *q = qdisc_priv(sch);
    return skb_peek(&q->q);
}

/* Reset the qdisc */
static void myfifo_reset(struct Qdisc *sch)
{
    struct myfifo_sched_data *q = qdisc_priv(sch);
    skb_queue_purge(&q->q);
    sch->q.qlen = 0;
    q->seq_a = 0;
    q->seq_b = 0;
    q->seq_c = 0;
}

/* Dummy change function */
static int myfifo_change(struct Qdisc *sch, struct nlattr *opt,
                         struct netlink_ext_ack *extack)
{
    return 0;
}

/* Destroy function */
static void myfifo_destroy(struct Qdisc *sch)
{
    myfifo_reset(sch);
}

/* Qdisc operations structure */
static struct Qdisc_ops myfifo_qdisc_ops __read_mostly = {
    .id         = "myfifo",
    .priv_size  = sizeof(struct myfifo_sched_data),
    .enqueue    = myfifo_enqueue,
    .dequeue    = myfifo_dequeue,
    .peek       = myfifo_peek,
    .init       = myfifo_init,
    .reset      = myfifo_reset,
    .change     = myfifo_change,
    .destroy    = myfifo_destroy,
    .owner      = THIS_MODULE,
};

static int __init myfifo_module_init(void)
{
    int ret = register_qdisc(&myfifo_qdisc_ops);
    if (ret)
        pr_err("myfifo: failed to register qdisc\n");
    else
        pr_info("myfifo: qdisc registered successfully\n");
    return ret;
}

static void __exit myfifo_module_exit(void)
{
    unregister_qdisc(&myfifo_qdisc_ops);
    pr_info("myfifo: qdisc unregistered\n");
}

module_init(myfifo_module_init);
module_exit(myfifo_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Custom Qdisc for two flows with specific logging");