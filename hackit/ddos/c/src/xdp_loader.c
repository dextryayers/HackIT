#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "../include/xdp_kern.h"
#include "../include/engine.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"

static struct bpf_object *g_xdp_obj = NULL;

int xdp_attach(const char *ifname, struct bpf_object **obj)
{
    struct bpf_program *prog;
    int ifindex, fd, err;

    if (!ifname || !obj)
        return -1;

    *obj = bpf_object__open_file("xdp_kern.o", NULL);
    if (libbpf_get_error(*obj)) {
        fprintf(stderr, "xdp_attach: bpf_object__open_file() failed: %s\n",
                strerror(errno));
        *obj = NULL;
        return -1;
    }

    err = bpf_object__load(*obj);
    if (err) {
        fprintf(stderr, "xdp_attach: bpf_object__load() failed: %d\n", err);
        bpf_object__close(*obj);
        *obj = NULL;
        return -1;
    }

    prog = bpf_object__find_program_by_name(*obj, "xdp_prog_main");
    if (!prog) {
        fprintf(stderr, "xdp_attach: bpf_object__find_program_by_name() "
                        "failed\n");
        bpf_object__close(*obj);
        *obj = NULL;
        return -1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "xdp_attach: if_nametoindex(%s): %s\n",
                ifname, strerror(errno));
        bpf_object__close(*obj);
        *obj = NULL;
        return -1;
    }

    fd = bpf_program__fd(prog);
    err = bpf_xdp_attach(ifindex, fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "xdp_attach: bpf_xdp_attach(%d, %d): %s\n",
                ifindex, fd, strerror(-err));
        bpf_object__close(*obj);
        *obj = NULL;
        return -1;
    }

    g_xdp_obj = *obj;
    return 0;
}

int xdp_detach(const char *ifname, struct bpf_object *obj)
{
    int ifindex, err;

    if (!ifname)
        return -1;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "xdp_detach: if_nametoindex(%s): %s\n",
                ifname, strerror(errno));
        return -1;
    }

    err = bpf_xdp_attach(ifindex, -1, 0, NULL);
    if (err) {
        fprintf(stderr, "xdp_detach: bpf_xdp_attach(%d, -1): %s\n",
                ifindex, strerror(-err));
        return -1;
    }

    if (obj) {
        bpf_object__close(obj);
    }

    if (g_xdp_obj == obj)
        g_xdp_obj = NULL;

    return 0;
}

int xdp_update_config(const char *ifname, struct xdp_config_t *cfg)
{
    struct bpf_map *map;
    struct xdp_config_key key;

    (void)ifname;

    if (!cfg)
        return -1;

    if (!g_xdp_obj) {
        fprintf(stderr, "xdp_update_config: no BPF object loaded\n");
        return -1;
    }

    map = bpf_object__find_map_by_name(g_xdp_obj, "xdp_config_map");
    if (!map) {
        fprintf(stderr, "xdp_update_config: map 'xdp_config_map' not found\n");
        return -1;
    }

    memset(&key, 0, sizeof(key));
    key.ifindex = 0;

    if (bpf_map__update_elem(map, &key, sizeof(key),
                             cfg, sizeof(*cfg), BPF_ANY) != 0) {
        fprintf(stderr, "xdp_update_config: bpf_map__update_elem() failed: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}

int xdp_read_stats(const char *ifname, struct xdp_stats_t *stats)
{
    struct bpf_map *map;
    struct xdp_stats_key key;

    (void)ifname;

    if (!stats)
        return -1;

    if (!g_xdp_obj) {
        fprintf(stderr, "xdp_read_stats: no BPF object loaded\n");
        return -1;
    }

    map = bpf_object__find_map_by_name(g_xdp_obj, "xdp_stats_map");
    if (!map) {
        fprintf(stderr, "xdp_read_stats: map 'xdp_stats_map' not found\n");
        return -1;
    }

    memset(&key, 0, sizeof(key));
    key.cpu = 0;

    if (bpf_map__lookup_elem(map, &key, sizeof(key),
                             stats, sizeof(*stats), 0) != 0) {
        fprintf(stderr, "xdp_read_stats: bpf_map__lookup_elem() failed: %s\n",
                strerror(errno));
        return -1;
    }

    return 0;
}

#pragma GCC diagnostic pop
