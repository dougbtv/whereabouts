#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <replica_count>"
    exit 1
fi

REPLICA_COUNT=$1

# Create the NAD
cat <<EOF > nad.yml
---
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: bridge-conf
spec:
  config: '{
    "cniVersion": "0.3.1",
    "name": "bridge-whereabouts",
    "type": "bridge",
    "bridge": "cni0",
    "mode": "bridge",
    "ipam": {
        "type": "whereabouts",
        "range": "10.10.0.0/16"
    }
}'
EOF

# Create the ReplicaSet YAML file
cat <<EOF > replicaset.yml
---
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: sample-replicaset
spec:
  replicas: $REPLICA_COUNT
  selector:
    matchLabels:
      app: samplepod-bridge
  template:
    metadata:
      labels:
        app: samplepod-bridge
      annotations:
        k8s.v1.cni.cncf.io/networks: bridge-conf
    spec:
      containers:
      - name: samplepod-bridge
        command: ["/bin/ash", "-c", "trap : TERM INT; sleep infinity & wait"]
        image: quay.io/dosmith/alpine:latest
        imagePullPolicy: IfNotPresent
EOF

# Apply the ReplicaSet YAML
kubectl apply -f nad.yml
kubectl apply -f replicaset.yml

# Check if all replicas are in 'Running' state
start_time=$(date +%s)
while true; do
    running=$(kubectl get replicasets sample-replicaset -o=jsonpath='{.status.readyReplicas}')
    if [[ "$running" == "$REPLICA_COUNT" ]]; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "All replicas are in 'Running' state! Took ${duration} seconds."
        break
    fi
    sleep 1
done
