# Hacking on the admission controller

I've been using a kubernetes cluster with a single worker. So everything happens on one host for convenience of devleopsment.

Run `./hack/build-go.sh` as usual.

Then, I have a way to scp the binaries onto the single worker host:

```
./hack/admission_controller/scp-build.sh
```

NOTE: The admission controller can't be running with the mount, otherwise you'll get a write failed due to the file being open on scp.

Tailor to your environment, and the following paths.

## Webhook

The webhook is created in the `/tmp`` directory and then I have `doc/crds/admission-debug.daemonset-install.yaml` which has a way to mount the binary from a temp file.

Create whereabouts given that.

Now... watch the pods until they come up.

And you can get the logs with:

```
kubectl get pods -n kube-system | awk '{print $1}' | grep -i webhook | xargs -I {} kubectl logs {} -n kube-system -f
```

You can then clean it all up with:

```
#!/bin/bash
kubectl delete -f doc/crds/daemonset-install.yaml
kubectl delete ippools.whereabouts.cni.cncf.io 10.10.0.0-16 -n kube-system
kubectl get overlappingrangeipreservations.whereabouts.cni.cncf.io -n kube-system | awk '{print $1}' | grep -v NAME | xargs -L1 -I{} kubectl delete overlappingrangeipreservations.whereabouts.cni.cncf.io {} -n kube-system
kubectl get pods -A | grep -i replicaset | awk '{print $2}' | xargs -L1 -I{} kubectl delete pod {} --grace-period=0 --force
```






## CNI binaries

Then, on that host, I have a few things I do in `/etc/cni/net.d/whereabouts.d`

First I create a debug config, `debug.whereabouts.conf`

```
{
  "datastore": "kubernetes",
  "kubernetes": {
    "kubeconfig": "/etc/cni/net.d/whereabouts.d/whereabouts.kubeconfig"
  },
  "log_level": "debug",
  "log_file": "/tmp/whereabouts.log",
  "reconciler_cron_expression": "30 4 * * *"
}
```

Then I have a `devsetup.sh`

```
#!/bin/bash

cp debug.whereabouts.conf whereabouts.conf
cp /home/fedora/whereabouts2 /opt/cni/bin/whereabouts
> /tmp/whereabouts.log
tail -f /tmp/whereabouts.log
```

Be sure to copy the modified cni binary because it's critical.


## Scaling notes

edit `/etc/kubernetes/madpods.conf`

```
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
maxPods: 250
```

Then edit `/var/lib/kubelet/kubeadm-flags.env`

```
KUBELET_KUBEADM_ARGS="--container-runtime-endpoint=unix:///var/run/crio/crio.sock --pod-infra-container-image=registry.k8s.io/pause:3.9 --config=/etc/kubernetes/madpods.conf"
```

Adding just the end one.

```
systemctl restart kubelet
```

And check with...

```
kubectl get node labkubedualhost-node-1 -ojsonpath='{.status.capacity.pods}'
```

And then I ran into issues with Flannel number of IPs available! lol.

Initial result with 100 pods:

```
[fedora@labkubedualhost-master-1 whereabouts]$ ./timer.sh 100
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 24 seconds.
```

Bigger cluster, 5x workers, 350 pods:

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 350
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 113 seconds.
```

And... not better than current HEAD...

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 350
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 108 seconds.
```

And with the admission controller, 5x workers, 500 pods...

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 500
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 150 seconds.
```

And with HEAD, sliiiightly longer.

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 500
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 156 seconds.
```

And then 350 pods with QPS bumped to 1000

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 350
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 93 seconds.
```

And 99 seconds on a second go.

And then 350 pods with admission controller + overlappingranges disabled...

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 350
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 75 seconds.
```

Shaves 25% off huh.

And then I tried going super high @ 1mil QPS/burst...

```
[fedora@bigcluster-master-1 whereabouts]$ ./hack/timer.sh 350
networkattachmentdefinition.k8s.cni.cncf.io/bridge-conf unchanged
replicaset.apps/sample-replicaset created
All replicas are in 'Running' state! Took 86 seconds.
```

Not particularly faster, actually.