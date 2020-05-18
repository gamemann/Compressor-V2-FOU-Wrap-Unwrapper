# NFTables Setup
The following should be applied to the POP.

## Create Forward Table & Chain
We'll want to create the Compressor Forward table and chain by doing the following:

```
nft add table compressor_forward
nft -- add chain compressor_forward prerouting { type nat hook prerouting priority -100 \; }
nft add chain compressor_forward postrouting { type nat hook postrouting priority 100 \; }
```

## Forward Game Server Traffic
Now create a rule for forwarding traffic.

```
nft add rule compressor_forward prerouting ip daddr $ANYCAST_IP udp dport $SERVERPORT dnat to $GAMESERVERIP
```

## Masquerade Random
Next, we want to masquerade as a mapped source port:

```
nft add rule compressor_forward postrouting masquerade random
```