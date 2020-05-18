# TC Filter Commands
The following TC commands were used to get things working with this project.

## Delete Existing Qdiscs
You may delete existing qdiscs via:

```
tc qdisc del dev $DEV root
```

## Create Qdisc
Create a `qdisc` with the following:

```
tc qdisc add dev $DEV clsact
```

## Delete Existing Filters.
You may delete existing filters via:

```
tc filter del dev $DEV ingress

## Exclude game server traffic.
We want to exclude game server traffic. Therefore, we'll need to add a rule for each game server such as the following:

```
tc filter add dev $DEV ingress prio 1 u32 match ip dst $ANYCAST_ADDR/32 match ip dport 27015 0xffff action pass
```

The NFTables forwarding rules will pick this up afterwards and forward the traffic.

## FOU Unwrapper
The following `tc` command is used to load the FOU Unwrapper:

```
tc filter add dev $DEV ingress prio 2 u32 match ip dport 1337 0xffff match ip src $GAMESERVERIP/32 action pipe bpf obj FOU_Unwrap.o section unwrap
```

## FOU Wrapper
The following `tc` command is used to load the FOU Wrapper:

```
tc filter add dev $DEV ingress prio 3 u32 match ip dst $ANYCAST_ADDR/32 action pipe bpf obj FOU_Wrap.o section wrap
```