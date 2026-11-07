# Outbound network security

Omnom fetches URLs from users, subscribed feeds and ActivityPub messages. Those
requests must not inherit access to private services merely because the Omnom
server can reach them. Use both the application policy and a deployment egress
filter when operating an exposed instance.

## Application policy

Feed discovery, RSS/Atom parsing and refreshes, favicons, embedded feed images,
ActivityPub actor/object/avatar requests and deliveries, and downloaded bookmark
media use the shared outbound HTTP client. It permits HTTP and HTTPS to public
addresses. Loopback, private, link-local, multicast, unspecified, documentation,
shared-address and reserved destinations are rejected, including known metadata
addresses and IPv6 transition ranges that can embed an internal IPv4 address.

Every new connection resolves the hostname, checks all returned addresses and
connects to an approved IP directly. The HTTP Host and TLS server name remain the
original hostname. Redirects and later feed refreshes use the same policy; mixed
public/private DNS answers are rejected. TLS certificate verification remains
enabled. These clients connect directly and ignore `HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` and `NO_PROXY`: a proxy resolving a hostname independently could
bypass the destination check. Deployments that require an outbound proxy need
a separately enforced network policy; proxy environment variables do not route
these requests through it.

An administrator can allow an intentional internal feed at an exact address and
port in `config.yml`:

```yaml
outbound:
  allowed_private_destinations:
    - "192.168.1.10:8080"
    - "[fd00::10]:443"
```

The default is an empty list. Entries must contain a private or loopback IP and
a nonzero port. Hostnames, CIDRs, wildcards, link-local addresses and the known
AWS/Google IPv6 metadata addresses are not accepted. A hostname may resolve to
an allowed address, but every result still needs permission for that port.
Exceptions grant access to **every user and remote feed**, not just one
subscription. Allow only services that are safe to expose this way. Restart the
service after changing configuration. Invalid entries stop startup, including
the `update-feeds` command.

Existing subscriptions to private destinations stop updating unless explicitly
allowed. A blocked image cannot be downloaded into Omnom's resource storage.
Already stored content is not removed by this change.

The client policy covers the Go HTTP paths above. Chromium's own network stack,
administrator-configured OAuth providers, SMTP and database connections use
separate transports. The operating-system filter below covers traffic from the
service UID, including its child processes. Server-side Chromium snapshots are
disabled by default; enable them only with an isolated browser/network setup
that also accounts for its local debugging connection. Do not grant broad
loopback access to make browser debugging work.

## Linux process containment

`deploy/omnom-egress.nft` is an opt-in nftables ruleset for a **dedicated Omnom
UID**. It blocks connections to non-public IPv4/IPv6 destinations and metadata
services. It leaves other UIDs alone and permits replies to incoming requests,
including requests from a local reverse proxy. It does not grandfather existing
outbound connections to prohibited destinations.

1. Run Omnom under its own unprivileged account. Do not share this UID with other
   applications, run Omnom as root, or give it `CAP_NET_ADMIN`.
2. Copy the ruleset into your deployment configuration. Populate its empty
   `allowed_tcp4`, `allowed_udp4`, `allowed_tcp6` and `allowed_udp6` sets with the
   exact infrastructure destinations the process needs. For example, a local
   DNS resolver requires its address and port 53 in both TCP and UDP sets:

   ```nft
   set allowed_tcp4 {
       type ipv4_addr . inet_service;
       elements = { 127.0.0.53 . 53, 10.0.0.20 . 5432 }
   }
   set allowed_udp4 {
       type ipv4_addr . inet_service;
       elements = { 127.0.0.53 . 53 }
   }
   ```

   Add narrowly scoped SMTP, database, internal identity-provider or intentional
   internal-feed exceptions as needed. Never grant access to metadata services.
   These firewall exceptions do not automatically create application-level HTTP
   exceptions. Public IPs routed to internal services in your particular network
   must also be added to the blocked sets.
3. Check and apply the copied file, using the actual service account:

   ```sh
   sudo nft -D omnom_uid="$(id -u omnom)" -c -f /etc/omnom-egress.nft
   sudo nft -D omnom_uid="$(id -u omnom)" -f /etc/omnom-egress.nft
   sudo nft list table inet omnom_egress
   ```

   Applying the file atomically replaces only its `omnom_egress` table. It does
   not flush other firewall rules. Integrate the file with your system's firewall
   startup so the filter is restored before Omnom starts after a reboot.
4. Check login, public feed updates, DNS and any required infrastructure
   connections. The rules have counters on denied traffic. To remove this
   filter during a controlled rollback:

   ```sh
   sudo nft delete table inet omnom_egress
   ```

Do not use an administrator's desktop UID as the service UID. The filter would
also constrain their browsers, terminals and other processes.

## Docker containment

Host `OUTPUT` rules do not filter a bridge container's traffic. For a rootful
Docker deployment, install the same rules in the container's own network
namespace, using the numeric UID that runs Omnom (1000 in the default image):

```sh
OMNOM_CONTAINER_PID=$(docker inspect --format '{{.State.Pid}}' omnom)
sudo nsenter --target "$OMNOM_CONTAINER_PID" --net \
  nft -D omnom_uid=1000 -c -f /etc/omnom-egress.nft
sudo nsenter --target "$OMNOM_CONTAINER_PID" --net \
  nft -D omnom_uid=1000 -f /etc/omnom-egress.nft
```

Use a dedicated container network namespace; do not use these instructions with
host networking or a namespace shared with unrelated workloads. User-namespace
remapping/rootless Docker needs the host-mapped UID and runtime-specific network
controls instead of assuming UID 1000.

For Docker's embedded resolver, allow `127.0.0.11 . 53` in both IPv4 exception
sets. The rules account for Docker translating that destination to its internal
DNS listener ports. Other DNS servers need their actual addresses instead.

Arrange for the runtime to install the filter before exposing the application,
and reinstall it whenever Docker recreates the network namespace. Installing it
manually once is temporary containment. Keep the container unprivileged without
`NET_ADMIN`. The host administrator performs the namespace setup.

Until the network policy is in place, restrict the **whole service** to trusted
access, including the ActivityPub inbox and static resources. For example,
publish Docker's port only on loopback (`-p 127.0.0.1:7331:7331`) and use a VPN or
authenticated gateway. Remove any existing public port mapping or public proxy
route when doing so. Disabling signup or blocking `/add_feed` alone does not
cover existing subscriptions or the ActivityPub inbox.

