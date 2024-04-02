#!/bin/bash
./hack/build-go.sh && \
  scp -o ProxyCommand="ssh -W %h:%p root@192.168.50.200" bin/ip-control-loop fedora@192.168.122.35:/tmp/ip-control-loop && \
  scp -o ProxyCommand="ssh -W %h:%p root@192.168.50.200" bin/whereabouts fedora@192.168.122.35:/home/fedora/whereabouts2
