/*
 * dpdk_arp_client.c
 *
 * Unidirectional ARP requester using DPDK.
 * Sends ARP requests to a kernel‑managed server and learns its MAC.
 *
 * Prerequisites:
 * 1. Bind the NIC to a DPDK-compatible driver (e.g., vfio-pci or uio):
 *    sudo dpdk-devbind --bind=vfio-pci <PCI_DEVICE_ID>
 *
 * 2. Mount hugepages:
 *    sudo mount -t hugetlbfs nodev /mnt/huge
 *
 * Build and Run:
 *   gcc -O3 -march=native dpdk_arp_client.c -o dpdk_arp_client \
 *       $(pkg-config --cflags --libs libdpdk)
 *
 *   sudo ./dpdk_arp_client -l 0 -n 4 -- <port_id> <my_ip> <peer_ip>
 *
 * Example:
 *   sudo ./dpdk_arp_client -l 0 -n 4 -- 0 192.168.0.1 192.168.0.2
 */
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512
#define NUM_MBUFS (4096 - 1)
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define ARP_INTERVAL_SEC 1

static struct rte_mempool *mbuf_pool;
static uint16_t port_id;
static struct rte_ether_addr src_mac;
static struct rte_ether_addr peer_mac;
static uint32_t my_ip;
static uint32_t peer_ip;
static int peer_known = 0;

/* Build and send ARP request to peer_ip */
static void send_arp_request(void) {
    struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
    if (!pkt) return;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (void *)(eth + 1);
    pkt->data_len = sizeof(*eth) + sizeof(*arp);
    pkt->pkt_len = pkt->data_len;

    /* Ethernet header */
    rte_ether_addr_copy(&src_mac, &eth->s_addr);
    memset(&eth->d_addr, 0xff, RTE_ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    /* ARP header */
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    rte_ether_addr_copy(&src_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = rte_cpu_to_be_32(my_ip);
    memset(&arp->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp->arp_data.arp_tip = rte_cpu_to_be_32(peer_ip);

    rte_eth_tx_burst(port_id, 0, &pkt, 1);
    printf("ARP request sent to %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
           (peer_ip>>24)&0xFF, (peer_ip>>16)&0xFF,
           (peer_ip>>8)&0xFF, peer_ip&0xFF);
}

int main(int argc, char **argv) {
    if (argc != 4)
        rte_exit(EXIT_FAILURE, "Usage: %s <port_id> <my_ip> <peer_ip>\n", argv[0]);

    port_id = atoi(argv[1]);
    if (inet_pton(AF_INET, argv[2], &my_ip) != 1 ||
        inet_pton(AF_INET, argv[3], &peer_ip) != 1)
        rte_exit(EXIT_FAILURE, "Invalid IP address\n");
    my_ip = rte_be_to_cpu_32(my_ip);
    peer_ip = rte_be_to_cpu_32(peer_ip);

    /* Initialize DPDK */
    rte_eal_init(argc, argv);
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    struct rte_eth_conf port_conf = { .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN } };
    rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                           rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
    rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE,
                           rte_eth_dev_socket_id(port_id), NULL);
    rte_eth_dev_start(port_id);
    rte_eth_macaddr_get(port_id, &src_mac);

    printf("DPDK ARP client up. My IP: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ", peer: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
           (my_ip>>24)&0xFF,(my_ip>>16)&0xFF,(my_ip>>8)&0xFF,my_ip&0xFF,
           (peer_ip>>24)&0xFF,(peer_ip>>16)&0xFF,(peer_ip>>8)&0xFF,peer_ip&0xFF);

    uint64_t prev_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    struct rte_mbuf *rx_pkts[BURST_SIZE];

    while (!peer_known) {
        /* Periodically send ARP requests */
        uint64_t now = rte_rdtsc();
        if ((now - prev_tsc) > hz * ARP_INTERVAL_SEC) {
            send_arp_request();
            prev_tsc = now;
        }

        /* Process incoming ARP replies */
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, rx_pkts, BURST_SIZE);
        for (int i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = rx_pkts[i];
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_ARP) {
                struct rte_arp_hdr *arp = (void *)(eth + 1);
                uint32_t sip = rte_be_to_cpu_32(arp->arp_data.arp_sip);
                uint16_t op = rte_be_to_cpu_16(arp->arp_opcode);
                if (op == RTE_ARP_OP_REPLY && sip == peer_ip) {
                    rte_ether_addr_copy(&arp->arp_data.arp_sha, &peer_mac);
                    peer_known = 1;
                    printf("Learned peer MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           peer_mac.addr_bytes[0], peer_mac.addr_bytes[1],
                           peer_mac.addr_bytes[2], peer_mac.addr_bytes[3],
                           peer_mac.addr_bytes[4], peer_mac.addr_bytes[5]);
                }
            }
            rte_pktmbuf_free(m);
        }
    }

    printf("ARP learning complete. Exiting.\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    return 0;
}

/*
Add the following `meson.build` file into your `examples/` directory to build this program with Meson + Ninja:

# examples/meson.build

project('dpdk_arp_client', 'c',
  default_options : [
    'c_std=c11',
    'optimization=3'
  ]
)

dpdk_inc = dependency('libdpdk', method: 'pkg-config')

executable('dpdk_arp_client',
  'dpdk_arp_client.c',
  dependencies: [dpdk_inc],
  install: true,
  cpp_args: ['-march=native'],
)

# Usage from root of your project:
#   meson setup builddir --prefix=/usr/local
#   ninja -C builddir
#   ninja -C builddir install
*/
