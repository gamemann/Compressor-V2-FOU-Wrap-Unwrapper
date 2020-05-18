# TC Filter Commands
The following TC commands were used to get things working with this project.

## Create qdisc
Create a `qdisc` with the following:

```
tc qdisc add dev $DEV clsact
```

## FOU Unwrapper
The following `tc` command is used to load the FOU Unwrapper:

```
tc filter add dev $DEV ingress u32 match ip dport 1337 0xffff match ip src $GAMEMACHINEIP/32 action pipe bpf obj FOU_Unwrap.o section unwrap
```

## FOU Wrapper
The following `tc` command is used to load the FOU Wrapper:

```
tc filter add dev $DEV ingress u32 match ip dst $FORWARDIP/32 action pipe bpf obj FOU_Wrap.o section wrap
```

**Note** - This is not tested yet.