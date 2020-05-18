# Tunnel Commands
This is the setup for tunnels (mainly on the game server destination machine).

## Create Network Namespace
You may create the namespace with:

```
ip netns add $NSNAME
```

## Probe FOU
You'll want to enable FOU via:

```
modprobe fou
```

## Create IPIP FOU Tunnel
Next, you'll want to create the IPIP FOU tunnel inside of the namespace. Use the following:

```
ip netns exec $NSNAME ip link add $IPIPDEV type ipip remote $ANYCAST_ADDR ttl 225 encap fou encap-sport 1337 encap-dport 1337
ip netns exec $NSNAME ip addr add $INTERNAL_IP/32 dev $IPIPDEV
ip netns exec $NSNAME ip link set $IPIPDEV up
ip netns exec $NSNAME ip route add default dev $IPIPDEV
```

## Create Veth Pair
Next, you'll want to create the veth pair and bridge:

```
ip link add dev veth1 type veth peer name veth2
ip link set veth1 up
ip link set veth2 netns $NSNAME
ip netns exec $NSNAME ip addr add 172.2.0.2/16 dev veth2
ip netns exec $NSNAME ip link set veth2 up
```

## Create Bridge
You'll want to then create a bridge and connect it to the veth peer on the host.

```
ip link add dev br0 type bridge
ip addr add 172.2.0.1/16 dev br0
ip link set br0 up

ip link set veth1 master br0
```

## Add Routes Inside Of Namespace
You'll want to add routes to the Anycast and POP IPs to go out the veth pair:

```
ip netns exec $NSNAME ip route add $POPIP via 172.2.0.1 dev veth2
ip netns exec $NSNAME ip route add $ANYCAST_ADDR via 172.2.0.1 dev veth2
```

## Forward Game Server Traffic
Forward game server traffic (UDP port 27015) to the veth peer inside of the namespace by doing:

```
iptables -t nat -I PREROUTING ! -s 172.2.0.0/16 -d $GAMESERVERIP -p udp --dport 27015 -j DNAT --to-destination 172.2.0.2:27015
```

## Accept Forwards
Accept forwards for the following devices:

```
iptables -A FORWARD -i $MAINDEV -j ACCEPT
iptables -A FORWARD -i br0 -j ACCEPT
```

## Masquerade From Bridge
Finally, you'll want to masquerade packets coming from the bridge:

```
iptables -t nat -A POSTROUTING -s 172.2.0.0/16 -j MASQUERADE
```

**Note** - This may not be needed.

## Add FOU Port Inside Namespace
You'll need to add the FOU port inside of the namespace via:

```
ip netns exec $NSNAME ip fou add port 1337 ipproto 4
```