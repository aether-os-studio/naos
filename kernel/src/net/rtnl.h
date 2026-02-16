#pragma once

#include <net/netlink.h>
#include <libs/klibc.h>

struct nlmsghdr {
    uint32_t nlmsg_len;   /* Length of message including header */
    uint16_t nlmsg_type;  /* Message type (RTM_*) */
    uint16_t nlmsg_flags; /* Additional flags */
    uint32_t nlmsg_seq;   /* Sequence number */
    uint32_t nlmsg_pid;   /* Sending process port ID */
};

/* Alignment macros */
#define NLMSG_ALIGNTO 4U
#define NLMSG_ALIGN(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLMSG_HDRLEN ((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh) ((void *)((char *)(nlh) + NLMSG_HDRLEN))
#define NLMSG_NEXT(nlh, len)                                                   \
    ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len),                                   \
     (struct nlmsghdr *)((char *)(nlh) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh, len)                                                     \
    ((len) >= (int)sizeof(struct nlmsghdr) &&                                  \
     (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh, len) ((nlh)->nlmsg_len - NLMSG_SPACE(len))

/* Standard message types */
#define NLMSG_NOOP 0x1
#define NLMSG_ERROR 0x2
#define NLMSG_DONE 0x3
#define NLMSG_OVERRUN 0x4

/* Netlink message flags */
#define NLM_F_REQUEST 0x001   /* It is request message */
#define NLM_F_MULTI 0x002     /* Multipart message */
#define NLM_F_ACK 0x004       /* Reply with ack */
#define NLM_F_ECHO 0x008      /* Echo this request */
#define NLM_F_DUMP_INTR 0x010 /* Dump was inconsistent */

/* GET request flags */
#define NLM_F_ROOT 0x100   /* Return complete table */
#define NLM_F_MATCH 0x200  /* Return all matching */
#define NLM_F_ATOMIC 0x400 /* Atomic GET */
#define NLM_F_DUMP (NLM_F_ROOT | NLM_F_MATCH)

/* NEW request flags */
#define NLM_F_REPLACE 0x100 /* Override existing */
#define NLM_F_EXCL 0x200    /* Do not touch if exists */
#define NLM_F_CREATE 0x400  /* Create if not exists */
#define NLM_F_APPEND 0x800  /* Add to end of list */

/* Netlink error message */
struct nlmsgerr {
    int error;           /* Negative errno or 0 for ack */
    struct nlmsghdr msg; /* Original message header that caused the error */
};

struct nlattr {
    uint16_t nla_len;  /* Length of attribute including header */
    uint16_t nla_type; /* Attribute type */
    /* followed by payload */
};

#define NLA_ALIGNTO 4U
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))
#define NLA_LEN(len) (NLA_HDRLEN + (len))
#define NLA_TOTAL_LEN(len) NLA_ALIGN(NLA_LEN(len))
#define NLA_NEXT(nla, attrlen)                                                 \
    ((attrlen) -= NLA_ALIGN((nla)->nla_len),                                   \
     (struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))
#define NLA_OK(nla, len)                                                       \
    ((len) >= (int)sizeof(struct nlattr) &&                                    \
     (nla)->nla_len >= sizeof(struct nlattr) && (nla)->nla_len <= (len))

/* NLA type mask - upper bits carry flags */
#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))

#define RTM_BASE 16
#define RTM_NEWLINK 16
#define RTM_DELLINK 17
#define RTM_GETLINK 18
#define RTM_SETLINK 19

#define RTM_NEWADDR 20
#define RTM_DELADDR 21
#define RTM_GETADDR 22

#define RTM_NEWROUTE 24
#define RTM_DELROUTE 25
#define RTM_GETROUTE 26

#define RTM_NEWNEIGH 28
#define RTM_DELNEIGH 29
#define RTM_GETNEIGH 30

#define RTM_NEWRULE 32
#define RTM_DELRULE 33
#define RTM_GETRULE 34

#define RTM_NEWQDISC 36
#define RTM_DELQDISC 37
#define RTM_GETQDISC 38

#define RTM_NEWTCLASS 40
#define RTM_DELTCLASS 41
#define RTM_GETTCLASS 42

#define RTM_NEWTFILTER 44
#define RTM_DELTFILTER 45
#define RTM_GETTFILTER 46

#define RTM_NEWNETCONF 80
#define RTM_DELNETCONF 81
#define RTM_GETNETCONF 82

#define RTM_MAX 83

/* Helper to get message family from type */
#define RTM_FAM(cmd) ((cmd) - RTM_BASE)
#define RTM_NR_MSGTYPES (RTM_MAX - RTM_BASE + 1)
#define RTM_NR_FAMILIES (RTM_NR_MSGTYPES >> 2)

#define RTNLGRP_NONE 0
#define RTNLGRP_LINK 1
#define RTNLGRP_NOTIFY 2
#define RTNLGRP_NEIGH 3
#define RTNLGRP_TC 4
#define RTNLGRP_IPV4_IFADDR 5
#define RTNLGRP_IPV4_MROUTE 6
#define RTNLGRP_IPV4_ROUTE 7
#define RTNLGRP_IPV4_RULE 8
#define RTNLGRP_IPV6_IFADDR 9
#define RTNLGRP_IPV6_MROUTE 10
#define RTNLGRP_IPV6_ROUTE 11
#define RTNLGRP_IPV6_RULE 18
#define RTNLGRP_MAX 32

/* Convert group number to bitmask */
#define RTNLGRP_TO_MASK(grp) (1U << ((grp) - 1))

struct ifinfomsg {
    uint8_t ifi_family; /* AF_UNSPEC */
    uint8_t __ifi_pad;
    uint16_t ifi_type;   /* ARPHRD_* */
    int32_t ifi_index;   /* Interface index */
    uint32_t ifi_flags;  /* IFF_* flags */
    uint32_t ifi_change; /* IFF_* change mask */
};

/* Interface flags (IFF_*) */
#define IFF_UP 0x0001
#define IFF_BROADCAST 0x0002
#define IFF_DEBUG 0x0004
#define IFF_LOOPBACK 0x0008
#define IFF_POINTOPOINT 0x0010
#define IFF_NOTRAILERS 0x0020
#define IFF_RUNNING 0x0040
#define IFF_NOARP 0x0080
#define IFF_PROMISC 0x0100
#define IFF_ALLMULTI 0x0200
#define IFF_MASTER 0x0400
#define IFF_SLAVE 0x0800
#define IFF_MULTICAST 0x1000
#define IFF_PORTSEL 0x2000
#define IFF_AUTOMEDIA 0x4000
#define IFF_DYNAMIC 0x8000
#define IFF_LOWER_UP 0x10000
#define IFF_DORMANT 0x20000
#define IFF_ECHO 0x40000

/* ARPHRD types */
#define ARPHRD_LOOPBACK 772
#define ARPHRD_ETHER 1
#define ARPHRD_NONE 0xFFFE

/* IFLA attributes for link messages */
enum {
    IFLA_UNSPEC,
    IFLA_ADDRESS,   /* Hardware address (MAC) */
    IFLA_BROADCAST, /* Broadcast address */
    IFLA_IFNAME,    /* Interface name */
    IFLA_MTU,       /* MTU */
    IFLA_LINK,      /* Link type */
    IFLA_QDISC,     /* Queueing discipline */
    IFLA_STATS,     /* Interface statistics */
    IFLA_COST,
    IFLA_PRIORITY,
    IFLA_MASTER,
    IFLA_WIRELESS,
    IFLA_PROTINFO,
    IFLA_TXQLEN, /* Transmit queue length */
    IFLA_MAP,
    IFLA_WEIGHT,
    IFLA_OPERSTATE, /* Operational state (RFC2863) */
    IFLA_LINKMODE,
    IFLA_LINKINFO,
    IFLA_NET_NS_PID,
    IFLA_IFALIAS,
    IFLA_NUM_VF,
    IFLA_VFINFO_LIST,
    IFLA_STATS64, /* 64-bit statistics */
    IFLA_VF_PORTS,
    IFLA_PORT_SELF,
    IFLA_AF_SPEC,
    IFLA_GROUP,
    IFLA_NET_NS_FD,
    IFLA_EXT_MASK,
    IFLA_PROMISCUITY,
    IFLA_NUM_TX_QUEUES,
    IFLA_NUM_RX_QUEUES,
    IFLA_CARRIER,
    IFLA_PHYS_PORT_ID,
    IFLA_CARRIER_CHANGES,
    IFLA_PHYS_SWITCH_ID,
    IFLA_LINK_NETNSID,
    IFLA_PHYS_PORT_NAME,
    IFLA_PROTO_DOWN,
    IFLA_GSO_MAX_SEGS,
    IFLA_GSO_MAX_SIZE,
    IFLA_PAD,
    IFLA_XDP,
    IFLA_EVENT,
    IFLA_NEW_NETNSID,
    IFLA_IF_NETNSID,
    IFLA_CARRIER_UP_COUNT,
    IFLA_CARRIER_DOWN_COUNT,
    IFLA_NEW_IFINDEX,
    IFLA_MIN_MTU,
    IFLA_MAX_MTU,
    __IFLA_MAX
};
#define IFLA_MAX (__IFLA_MAX - 1)

#define RTNL_WIFI_CMD_MAGIC 0x57494649U
#define RTNL_WIFI_CMD_VERSION 1U

enum rtnl_wifi_cmd_type {
    RTNL_WIFI_CMD_SET_TX_CTX = 1,
    RTNL_WIFI_CMD_SET_BSSID = 2,
    RTNL_WIFI_CMD_CONNECT_OPEN = 3,
    RTNL_WIFI_CMD_DISCONNECT = 4,
    RTNL_WIFI_CMD_CONNECT_OPEN_BSSID = 5,
};

struct rtnl_wifi_cmd_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t cmd;
    uint16_t payload_len;
    uint16_t reserved;
} __attribute__((packed));

struct rtnl_wifi_set_tx_ctx {
    uint16_t wlan_idx;
    uint8_t own_mac_idx;
    uint8_t reserved;
} __attribute__((packed));

struct rtnl_wifi_set_bssid {
    uint8_t bssid[6];
    uint8_t reserved[2];
} __attribute__((packed));

struct rtnl_wifi_connect_open {
    uint8_t ssid_len;
    uint8_t reserved[3];
    char ssid[32];
} __attribute__((packed));

struct rtnl_wifi_connect_open_bssid {
    uint8_t bssid[6];
    uint8_t ssid_len;
    uint8_t reserved;
    char ssid[32];
} __attribute__((packed));

/* Operational states */
enum {
    IF_OPER_UNKNOWN,
    IF_OPER_NOTPRESENT,
    IF_OPER_DOWN,
    IF_OPER_LOWERLAYERDOWN,
    IF_OPER_TESTING,
    IF_OPER_DORMANT,
    IF_OPER_UP,
};

struct ifaddrmsg {
    uint8_t ifa_family;    /* Address family (AF_INET/AF_INET6) */
    uint8_t ifa_prefixlen; /* Prefix length */
    uint8_t ifa_flags;     /* Address flags */
    uint8_t ifa_scope;     /* Address scope */
    uint32_t ifa_index;    /* Interface index */
};

/* IFA attributes */
enum {
    IFA_UNSPEC,
    IFA_ADDRESS,   /* Interface address */
    IFA_LOCAL,     /* Local address */
    IFA_LABEL,     /* Interface name */
    IFA_BROADCAST, /* Broadcast address */
    IFA_ANYCAST,   /* Anycast address */
    IFA_CACHEINFO, /* Address cache info */
    IFA_MULTICAST,
    IFA_FLAGS, /* Extended flags */
    IFA_RT_PRIORITY,
    IFA_TARGET_NETNSID,
    __IFA_MAX
};
#define IFA_MAX (__IFA_MAX - 1)

/* IFA flags */
#define IFA_F_SECONDARY 0x01
#define IFA_F_TEMPORARY IFA_F_SECONDARY
#define IFA_F_NODAD 0x02
#define IFA_F_OPTIMISTIC 0x04
#define IFA_F_DADFAILED 0x08
#define IFA_F_HOMEADDRESS 0x10
#define IFA_F_DEPRECATED 0x20
#define IFA_F_TENTATIVE 0x40
#define IFA_F_PERMANENT 0x80
#define IFA_F_MANAGETEMPADDR 0x100
#define IFA_F_NOPREFIXROUTE 0x200
#define IFA_F_MCAUTOJOIN 0x400
#define IFA_F_STABLE_PRIVACY 0x800

/* Address scopes */
enum rt_scope_t {
    RT_SCOPE_UNIVERSE = 0,
    RT_SCOPE_SITE = 200,
    RT_SCOPE_LINK = 253,
    RT_SCOPE_HOST = 254,
    RT_SCOPE_NOWHERE = 255,
};

struct rtmsg {
    uint8_t rtm_family;   /* Address family */
    uint8_t rtm_dst_len;  /* Destination prefix length */
    uint8_t rtm_src_len;  /* Source prefix length */
    uint8_t rtm_tos;      /* TOS filter */
    uint8_t rtm_table;    /* Routing table ID */
    uint8_t rtm_protocol; /* Routing protocol */
    uint8_t rtm_scope;    /* Distance to destination */
    uint8_t rtm_type;     /* Route type */
    uint32_t rtm_flags;   /* Route flags */
};

/* Route types */
enum {
    RTN_UNSPEC,
    RTN_UNICAST,     /* Gateway or direct route */
    RTN_LOCAL,       /* Accept locally */
    RTN_BROADCAST,   /* Accept as broadcast */
    RTN_ANYCAST,     /* Accept as anycast */
    RTN_MULTICAST,   /* Multicast route */
    RTN_BLACKHOLE,   /* Drop packets */
    RTN_UNREACHABLE, /* Destination unreachable */
    RTN_PROHIBIT,    /* Administratively prohibited */
    RTN_THROW,       /* Routing lookup in another table */
    RTN_NAT,         /* Network address translation */
    RTN_XRESOLVE,    /* External resolver */
    __RTN_MAX
};
#define RTN_MAX (__RTN_MAX - 1)

/* Route protocols (who installed the route) */
#define RTPROT_UNSPEC 0
#define RTPROT_REDIRECT 1
#define RTPROT_KERNEL 2
#define RTPROT_BOOT 3
#define RTPROT_STATIC 4
#define RTPROT_DHCP 16
#define RTPROT_RA 9

/* Route table IDs */
enum rt_class_t {
    RT_TABLE_UNSPEC = 0,
    RT_TABLE_COMPAT = 252,
    RT_TABLE_DEFAULT = 253,
    RT_TABLE_MAIN = 254,
    RT_TABLE_LOCAL = 255,
};

/* RTA attributes */
enum {
    RTA_UNSPEC,
    RTA_DST,      /* Destination address */
    RTA_SRC,      /* Source address */
    RTA_IIF,      /* Input interface index */
    RTA_OIF,      /* Output interface index */
    RTA_GATEWAY,  /* Gateway address */
    RTA_PRIORITY, /* Route priority/metric */
    RTA_PREFSRC,  /* Preferred source address */
    RTA_METRICS,  /* Route metrics */
    RTA_MULTIPATH,
    RTA_PROTOINFO,
    RTA_FLOW,
    RTA_CACHEINFO,
    RTA_SESSION,
    RTA_MP_ALGO,
    RTA_TABLE, /* Routing table ID */
    RTA_MARK,
    RTA_MFC_STATS,
    RTA_VIA,
    RTA_NEWDST,
    RTA_PREF,
    RTA_ENCAP_TYPE,
    RTA_ENCAP,
    RTA_EXPIRES,
    RTA_PAD,
    RTA_UID,
    RTA_TTL_PROPAGATE,
    __RTA_MAX
};
#define RTA_MAX (__RTA_MAX - 1)

/* Route flags */
#define RTM_F_NOTIFY 0x100
#define RTM_F_CLONED 0x200
#define RTM_F_EQUALIZE 0x400
#define RTM_F_PREFIX 0x800
#define RTM_F_LOOKUP_TABLE 0x1000

struct ifa_cacheinfo {
    uint32_t ifa_prefered;
    uint32_t ifa_valid;
    uint32_t cstamp; /* Created timestamp (jiffies) */
    uint32_t tstamp; /* Updated timestamp (jiffies) */
};

struct rtnl_link_stats {
    uint32_t rx_packets;
    uint32_t tx_packets;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t rx_errors;
    uint32_t tx_errors;
    uint32_t rx_dropped;
    uint32_t tx_dropped;
    uint32_t multicast;
    uint32_t collisions;
    /* detailed rx errors */
    uint32_t rx_length_errors;
    uint32_t rx_over_errors;
    uint32_t rx_crc_errors;
    uint32_t rx_frame_errors;
    uint32_t rx_fifo_errors;
    uint32_t rx_missed_errors;
    /* detailed tx errors */
    uint32_t tx_aborted_errors;
    uint32_t tx_carrier_errors;
    uint32_t tx_fifo_errors;
    uint32_t tx_heartbeat_errors;
    uint32_t tx_window_errors;
    /* for cslip etc */
    uint32_t rx_compressed;
    uint32_t tx_compressed;
    uint32_t rx_nohandler;
};

struct rtnl_link_stats64 {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
    uint64_t multicast;
    uint64_t collisions;
    uint64_t rx_length_errors;
    uint64_t rx_over_errors;
    uint64_t rx_crc_errors;
    uint64_t rx_frame_errors;
    uint64_t rx_fifo_errors;
    uint64_t rx_missed_errors;
    uint64_t tx_aborted_errors;
    uint64_t tx_carrier_errors;
    uint64_t tx_fifo_errors;
    uint64_t tx_heartbeat_errors;
    uint64_t tx_window_errors;
    uint64_t rx_compressed;
    uint64_t tx_compressed;
    uint64_t rx_nohandler;
};

#define IFNAMSIZ 16
#define MAX_ADDR_LEN 32
#define MAX_NET_DEVICES 64
#define MAX_IF_ADDRS 16

struct net_device_addr {
    uint8_t family;    /* AF_INET or AF_INET6 */
    uint8_t prefixlen; /* Prefix length */
    uint8_t flags;     /* IFA_F_* */
    uint8_t scope;     /* RT_SCOPE_* */
    union {
        uint32_t ipv4;    /* IPv4 address in network byte order */
        uint8_t ipv6[16]; /* IPv6 address */
    } addr;
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } broadcast;
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } local;
    char label[IFNAMSIZ]; /* Interface label */
    struct ifa_cacheinfo cacheinfo;
};

struct net_device;
typedef int (*rtnl_wireless_cmd_t)(struct net_device *dev, const void *data,
                                   uint32_t len);

struct net_device {
    char name[IFNAMSIZ];
    int32_t ifindex;
    uint16_t type;  /* ARPHRD_* */
    uint32_t flags; /* IFF_* */
    uint32_t mtu;
    uint32_t txqlen;
    uint8_t addr[MAX_ADDR_LEN];      /* Hardware address */
    uint8_t broadcast[MAX_ADDR_LEN]; /* Broadcast address */
    uint8_t addr_len;
    uint8_t operstate; /* IF_OPER_* */
    char qdisc[IFNAMSIZ];

    /* Statistics */
    struct rtnl_link_stats64 stats;

    /* Addresses assigned to this device */
    struct net_device_addr addrs[MAX_IF_ADDRS];
    int num_addrs;

    bool active;
    spinlock_t lock;
    void *wireless_priv;
    rtnl_wireless_cmd_t wireless_cmd;
};

#define MAX_ROUTES 256

struct rt_entry {
    uint8_t family;  /* AF_INET / AF_INET6 */
    uint8_t dst_len; /* Destination prefix length */
    uint8_t src_len;
    uint8_t tos;
    uint8_t table;    /* RT_TABLE_* */
    uint8_t protocol; /* RTPROT_* */
    uint8_t scope;    /* RT_SCOPE_* */
    uint8_t type;     /* RTN_* */
    uint32_t flags;

    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } dst;

    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } gateway;

    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } prefsrc;

    int32_t oif;       /* Output interface index */
    uint32_t priority; /* Route metric/priority */

    bool active;
};

typedef int (*rtnl_doit_func)(struct nlmsghdr *nlh, uint32_t sender_pid,
                              struct netlink_sock *sender_sock);
typedef int (*rtnl_dumpit_func)(struct nlmsghdr *nlh, uint32_t sender_pid,
                                struct netlink_sock *sender_sock);

struct rtnl_link {
    rtnl_doit_func doit;
    rtnl_dumpit_func dumpit;
};

struct nla_builder {
    char *buf;
    size_t capacity;
    size_t offset; /* Current write position */
};

/* Initialize the RTNL subsystem */
void rtnl_init();

/* Process an incoming NETLINK_ROUTE message from the netlink layer */
int rtnl_process_msg(struct netlink_sock *sender_sock, const char *data,
                     size_t len, uint32_t sender_pid);

/* Register a message handler */
int rtnl_register(uint16_t msgtype, rtnl_doit_func doit,
                  rtnl_dumpit_func dumpit);

/* Network device management */
struct net_device *rtnl_dev_alloc(const char *name, uint16_t type);
struct net_device *rtnl_dev_get_by_index(int32_t ifindex);
struct net_device *rtnl_dev_get_by_name(const char *name);
int rtnl_dev_register(struct net_device *dev);
void rtnl_dev_unregister(struct net_device *dev);
void rtnl_dev_set_wireless_handler(struct net_device *dev, void *priv,
                                   rtnl_wireless_cmd_t handler);

/* Address management */
int rtnl_addr_add(int32_t ifindex, uint8_t family, const void *addr,
                  uint8_t prefixlen, uint8_t scope, uint8_t flags);
int rtnl_addr_del(int32_t ifindex, uint8_t family, const void *addr,
                  uint8_t prefixlen);

/* Route management */
int rtnl_route_add(struct rt_entry *route);
int rtnl_route_del(struct rt_entry *route);

/* Notification helpers (broadcast state changes) */
void rtnl_notify_link(struct net_device *dev, uint16_t event_type);
void rtnl_notify_addr(struct net_device *dev, struct net_device_addr *addr,
                      uint16_t event_type);
void rtnl_notify_route(struct rt_entry *route, uint16_t event_type);

/* NLA builder helpers */
void nla_builder_init(struct nla_builder *b, char *buf, size_t capacity);
int nla_put(struct nla_builder *b, uint16_t type, const void *data, size_t len);
int nla_put_u8(struct nla_builder *b, uint16_t type, uint8_t val);
int nla_put_u16(struct nla_builder *b, uint16_t type, uint16_t val);
int nla_put_u32(struct nla_builder *b, uint16_t type, uint32_t val);
int nla_put_u64(struct nla_builder *b, uint16_t type, uint64_t val);
int nla_put_string(struct nla_builder *b, uint16_t type, const char *str);

/* NLA parser helpers */
struct nlattr *nla_find(void *head, int len, uint16_t type);
void *nla_data(const struct nlattr *nla);
int nla_len(const struct nlattr *nla);
uint32_t nla_get_u32(const struct nlattr *nla);
uint16_t nla_get_u16(const struct nlattr *nla);
uint8_t nla_get_u8(const struct nlattr *nla);
const char *nla_get_string(const struct nlattr *nla);
