#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/byteorder/little_endian.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

// Define a shared eBPF Map to track our in-flight seq
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u16);
  __type(value, __u64);
} flight_tracker SEC(".maps");

// Define a Perf Event Ring Buffer to pass telemetry
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} packet_events SEC(".maps");

// Event structure payload mapped to user space
struct ping_event {
  __u32 src_ip;
  __u64 rtt_ns;
  __u16 seq;
};

SEC("xdp")
int monitor_icmp(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  if (ip->protocol != IPPROTO_ICMP)
    return XDP_PASS;

  struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
  if ((void *)(icmp + 1) > data_end)
    return XDP_PASS;

  if (icmp->type == ICMP_ECHO) {
    __u64 ts = bpf_ktime_get_ns();
    __u16 seq = __constant_ntohs(icmp->un.echo.sequence);

    bpf_map_update_elem(&flight_tracker, &seq, &ts, BPF_ANY);
    return XDP_PASS;
  }
  if (icmp->type == ICMP_ECHOREPLY) {
    __u16 seq = __constant_ntohs(icmp->un.echo.sequence);
    __u64 *start_ts = bpf_map_lookup_elem(&flight_tracker, &seq);

    if (start_ts) {
      __u64 now = bpf_ktime_get_ns();
      struct ping_event event = {};

      event.src_ip = ip->saddr;
      event.rtt_ns = now - *start_ts;
      event.seq = seq;

      bpf_map_delete_elem(&flight_tracker, &seq);

      bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU, &event,
                            sizeof(event));
    }
  }
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
