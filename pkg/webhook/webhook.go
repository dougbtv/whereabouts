package webhook

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	netclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/k8snetworkplumbingwg/whereabouts/pkg/config"
	"github.com/k8snetworkplumbingwg/whereabouts/pkg/logging"
	"github.com/k8snetworkplumbingwg/whereabouts/pkg/storage/kubernetes"
	"github.com/k8snetworkplumbingwg/whereabouts/pkg/types"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

var (
	codecs = serializer.NewCodecFactory(runtime.NewScheme())
)

func admissionReviewFromRequest(r *http.Request, deserializer runtime.Decoder) (*admissionv1.AdmissionReview, error) {
	// Validate that the incoming content type is correct.
	if r.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("expected application/json content-type")
	}

	// Get the body data, which will be the AdmissionReview
	// content for the request.
	var body []byte
	if r.Body != nil {
		requestData, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		body = requestData
	}

	// Decode the request body into
	admissionReviewRequest := &admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, admissionReviewRequest); err != nil {
		return nil, err
	}

	return admissionReviewRequest, nil
}

const (
	networkAttachmentAnnot = "k8s.v1.cni.cncf.io/networks"
)

// NoK8sNetworkError indicates error, no network in kubernetes
type NoK8sNetworkError struct {
	message string
}

func (e *NoK8sNetworkError) Error() string { return e.message }

// GetNetworkSelectionAnnotation gets net-attach-def annotation from pod
func GetNetworkSelectionAnnotation(pod *v1.Pod) ([]*types.NetworkSelectionElement, error) {
	// logging.Debugf("!bang GetNetworkSelectionAnnotation POD DETAILS: %v", pod)

	netAnnot := pod.Annotations[networkAttachmentAnnot]
	defaultNamespace := pod.ObjectMeta.Namespace

	if len(netAnnot) == 0 {
		return nil, &NoK8sNetworkError{"no Whereabouts networks found in selection"}
	}

	networks, err := parsePodNetworkAnnotation(netAnnot, defaultNamespace)
	if err != nil {
		return nil, err
	}
	return networks, nil
}

func parsePodNetworkAnnotation(podNetworks, defaultNamespace string) ([]*types.NetworkSelectionElement, error) {
	var networks []*types.NetworkSelectionElement

	logging.Debugf("parsePodNetworkAnnotation: %s, %s", podNetworks, defaultNamespace)
	if podNetworks == "" {
		return nil, logging.Errorf("parsePodNetworkAnnotation: pod annotation does not have \"network\" as key")
	}

	if strings.ContainsAny(podNetworks, "[{\"") {
		if err := json.Unmarshal([]byte(podNetworks), &networks); err != nil {
			return nil, logging.Errorf("parsePodNetworkAnnotation: failed to parse pod Network Attachment Selection Annotation JSON format: %v", err)
		}
	} else {
		// Comma-delimited list of network attachment object names
		for _, item := range strings.Split(podNetworks, ",") {
			// Remove leading and trailing whitespace.
			item = strings.TrimSpace(item)

			// Parse network name (i.e. <namespace>/<network name>@<ifname>)
			netNsName, networkName, netIfName, err := parsePodNetworkObjectName(item)
			if err != nil {
				return nil, logging.Errorf("parsePodNetworkAnnotation: %v", err)
			}

			networks = append(networks, &types.NetworkSelectionElement{
				Name:             networkName,
				Namespace:        netNsName,
				InterfaceRequest: netIfName,
			})
		}
	}

	for _, n := range networks {
		if n.Namespace == "" {
			n.Namespace = defaultNamespace
		}
		if n.MacRequest != "" {
			// validate MAC address
			if _, err := net.ParseMAC(n.MacRequest); err != nil {
				return nil, logging.Errorf("parsePodNetworkAnnotation: failed to mac: %v", err)
			}
		}
		if n.InfinibandGUIDRequest != "" {
			// validate GUID address
			if _, err := net.ParseMAC(n.InfinibandGUIDRequest); err != nil {
				return nil, logging.Errorf("parsePodNetworkAnnotation: failed to validate infiniband GUID: %v", err)
			}
		}
		if n.IPRequest != nil {
			for _, ip := range n.IPRequest {
				// validate IP address
				if strings.Contains(ip, "/") {
					if _, _, err := net.ParseCIDR(ip); err != nil {
						return nil, logging.Errorf("failed to parse CIDR %q: %v", ip, err)
					}
				} else if net.ParseIP(ip) == nil {
					return nil, logging.Errorf("failed to parse IP address %q", ip)
				}
			}
		}
		// compatibility pre v3.2, will be removed in v4.0
		if n.DeprecatedInterfaceRequest != "" && n.InterfaceRequest == "" {
			n.InterfaceRequest = n.DeprecatedInterfaceRequest
		}
	}

	return networks, nil
}

func parsePodNetworkObjectName(podnetwork string) (string, string, string, error) {
	var netNsName string
	var netIfName string
	var networkName string

	logging.Debugf("parsePodNetworkObjectName: %s", podnetwork)
	slashItems := strings.Split(podnetwork, "/")
	if len(slashItems) == 2 {
		netNsName = strings.TrimSpace(slashItems[0])
		networkName = slashItems[1]
	} else if len(slashItems) == 1 {
		networkName = slashItems[0]
	} else {
		return "", "", "", logging.Errorf("parsePodNetworkObjectName: Invalid network object (failed at '/')")
	}

	atItems := strings.Split(networkName, "@")
	networkName = strings.TrimSpace(atItems[0])
	if len(atItems) == 2 {
		netIfName = strings.TrimSpace(atItems[1])
	} else if len(atItems) != 1 {
		return "", "", "", logging.Errorf("parsePodNetworkObjectName: Invalid network object (failed at '@')")
	}

	// Check and see if each item matches the specification for valid attachment name.
	// "Valid attachment names must be comprised of units of the DNS-1123 label format"
	// [a-z0-9]([-a-z0-9]*[a-z0-9])?
	// And we allow at (@), and forward slash (/) (units separated by commas)
	// It must start and end alphanumerically.
	allItems := []string{netNsName, networkName, netIfName}
	for i := range allItems {
		matched, _ := regexp.MatchString("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", allItems[i])
		if !matched && len([]rune(allItems[i])) > 0 {
			return "", "", "", logging.Errorf(fmt.Sprintf("parsePodNetworkObjectName: Failed to parse: one or more items did not match comma-delimited format (must consist of lower case alphanumeric characters). Must start and end with an alphanumeric character), mismatch @ '%v'", allItems[i]))
		}
	}

	logging.Debugf("parsePodNetworkObjectName: parsed: %s, %s, %s", netNsName, networkName, netIfName)
	return netNsName, networkName, netIfName, nil
}

// ProcessNetworkSelection returns delegatenetconf from net-attach-def annotation in pod
func ProcessNetworkSelection(pod *v1.Pod, networks []*types.NetworkSelectionElement) (map[string]string, error) {
	// logging.Debugf("ProcessNetworkSelection: %v, %v", pod, networks)
	cconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to implicitly generate the kubeconfig: %w", err)
	}

	nc, err := netclient.NewForConfig(cconfig)
	if err != nil {
		return nil, err
	}

	labellist := make(map[string]string)
	for idx, net := range networks {
		logging.Verbosef("!bang each ProcessNetworkSelection: %v / %v", net.Namespace, net.Name)
		netattach, err := nc.K8sCniCncfIoV1().NetworkAttachmentDefinitions(net.Namespace).Get(context.TODO(), net.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		logging.Verbosef("!bang ProcessNetworkSelection NET-ATTACH-DEF: %v", netattach)

		// NEXT!
		// We  need to parse the delegate to see if it's from Whereabouts
		if strings.Contains(netattach.Spec.Config, "whereabouts") {
			// Then we need to get the IPAM config from within it. Or do we? I don't think we do.
			// Then we need to emulate a CNI ADD...
			ipamConf, _, err := config.LoadIPAMConfig([]byte(netattach.Spec.Config), cniArgs(pod.Namespace, pod.Name))
			if err != nil {
				logging.Errorf("IPAM configuration load failed: %s", err)
				return nil, err
			}

			uuidPath := generateUUIDPath("whereabouts/tmp")
			logging.Verbosef("!bang UUID PATH: %v", uuidPath)

			k8sipam, err := kubernetes.NewKubernetesIPAM(uuidPath, *ipamConf)
			if err != nil {
				return nil, logging.Errorf("failed to create Kubernetes IPAM manager: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), types.AddTimeLimit)
			defer cancel()
			newips, err := kubernetes.IPManagementKubernetesUpdate(ctx, types.Allocate, k8sipam, *ipamConf, uuidPath, ipamConf.GetPodRef())

			logging.Verbosef("!bang NEWIPS: %v", newips)

			// When we go to set the label... we need to be award of our ordinality.
			// We need to label on ordinality and hope it matches up on the CNI exec side.
			// There's no promise of this, but it's the best we can do.
			// We need to get the ordinality from the pod, and then set the label on the pod.
			// Convert net.IPNet to a comma-separated string representation
			var ipsAsString []string
			for _, ipNet := range newips {
				// Replace the '/' character with '|'
				cidrString := strings.ReplaceAll(ipNet.String(), "/", "-")
				cidrString = strings.ReplaceAll(cidrString, ":", "_")
				ipsAsString = append(ipsAsString, cidrString)
			}
			ipsList := strings.Join(ipsAsString, ",")

			// Insert entry to the hashList map
			labellist[fmt.Sprintf("whereabouts-%d", idx)] = ipsList

		} else {
			return nil, &NoK8sNetworkError{"no Whereabouts networks found in selection"}
		}

	}

	return labellist, nil
}

func generateUUIDPath(prefix string) string {
	// Generate random bytes
	uuidBytes := make([]byte, 16)
	_, err := rand.Read(uuidBytes)
	if err != nil {
		panic(err)
	}

	// Set the version (4) and variant (2) bits
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40 // Version 4 (random)
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80 // Variant 2 (RFC 4122)

	// Format the UUID as a string
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x", uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])

	// Concatenate the prefix with the UUID string representation
	uuidPath := fmt.Sprintf("%s/%s", prefix, uuidStr)

	return uuidPath
}

func cniArgs(podNamespace string, podName string) string {
	return fmt.Sprintf("IgnoreUnknown=1;K8S_POD_NAMESPACE=%s;K8S_POD_NAME=%s", podNamespace, podName)
}

/*


		ipamConf, confVersion, err := config.LoadIPAMConfig(args.StdinData, args.Args)
		if err != nil {
			logging.Errorf("IPAM configuration load failed: %s", err)
			return err
		}
		logging.Debugf("ADD - IPAM configuration successfully read: %+v", *ipamConf)
		ipam, err := kubernetes.NewKubernetesIPAM(args.ContainerID, *ipamConf)
		if err != nil {
			return logging.Errorf("failed to create Kubernetes IPAM manager: %v", err)
		}
		defer func() { safeCloseKubernetesBackendConnection(ipam) }()
		return cmdAdd(args, ipam, confVersion)

---

func cmdAdd(args *skel.CmdArgs, client *kubernetes.KubernetesIPAM, cniVersion string) error {
	// Initialize our result, and assign DNS & routing.
	result := &current.Result{}
	result.DNS = client.Config.DNS
	result.Routes = client.Config.Routes

	logging.Debugf("Beginning IPAM for ContainerID: %v", args.ContainerID)
	var newips []net.IPNet

	ctx, cancel := context.WithTimeout(context.Background(), types.AddTimeLimit)
	defer cancel()

	newips, err := kubernetes.IPManagement(ctx, types.Allocate, client.Config, client)
	if err != nil {
		logging.Errorf("Error at storage engine: %s", err)
		return fmt.Errorf("error at storage engine: %w", err)
	}

	for _, newip := range newips {
		result.IPs = append(result.IPs, &current.IPConfig{
			Address: newip,
			Gateway: client.Config.Gateway})
	}

	// Assign all the static IP elements.
	for _, v := range client.Config.Addresses {
		result.IPs = append(result.IPs, &current.IPConfig{
			Address: v.Address,
			Gateway: v.Gateway})
	}

	return cnitypes.PrintResult(result, cniVersion)
}

---

Protocol parameters are passed to the plugins via OS environment variables.

CNI_COMMAND: indicates the desired operation; ADD, DEL, CHECK, GC, or VERSION.
CNI_CONTAINERID: Container ID. A unique plaintext identifier for a container, allocated by the runtime. Must not be empty. Must start with an alphanumeric character, optionally followed by any combination of one or more alphanumeric characters, underscore (), dot (.) or hyphen (-).
CNI_NETNS: A reference to the container's "isolation domain". If using network namespaces, then a path to the network namespace (e.g. /run/netns/[nsname])
CNI_IFNAME: Name of the interface to create inside the container; if the plugin is unable to use this interface name it must return an error.
CNI_ARGS: Extra arguments passed in by the user at invocation time. Alphanumeric key-value pairs separated by semicolons; for example, "FOO=BAR;ABC=123"
CNI_PATH: List of paths to search for CNI plugin executables. Paths are separated by an OS-specific list separator; for example ':' on Linux and ';' on Windows

---

func LoadArgs
func LoadArgs(args string, container interface{}) error
LoadArgs parses args from a string in the form "K=V;K2=V2;..."

*/

/*
func (c *ClientInfo) GetNetAttachDef(namespace, name string) (*nettypes.NetworkAttachmentDefinition, error) {
	if c.NetDefInformer != nil {
		logging.Debugf("GetNetAttachDef for [%s/%s] will use informer cache", namespace, name)
		return netlister.NewNetworkAttachmentDefinitionLister(c.NetDefInformer.GetIndexer()).NetworkAttachmentDefinitions(namespace).Get(name)
	}
	return c.NetClient.K8sCniCncfIoV1().NetworkAttachmentDefinitions(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}
*/

/*
func getKubernetesDelegate(client *ClientInfo, net *types.NetworkSelectionElement, confdir string, pod *v1.Pod, resourceMap map[string]*types.ResourceInfo) (*types.DelegateNetConf, map[string]*types.ResourceInfo, error) {

	logging.Debugf("getKubernetesDelegate: %v, %v, %s, %v, %v", client, net, confdir, pod, resourceMap)

	customResource, err := client.GetNetAttachDef(net.Namespace, net.Name)
	if err != nil {
		errMsg := fmt.Sprintf("cannot find a network-attachment-definition (%s) in namespace (%s): %v", net.Name, net.Namespace, err)
		if client != nil {
			client.Eventf(pod, v1.EventTypeWarning, "NoNetworkFound", errMsg)
		}
		return nil, resourceMap, logging.Errorf("getKubernetesDelegate: " + errMsg)
	}

	configBytes, err := netutils.GetCNIConfig(customResource, confdir)
	if err != nil {
		return nil, resourceMap, err
	}

	delegate, err := types.LoadDelegateNetConf(configBytes, net, deviceID, resourceName)
	if err != nil {
		return nil, resourceMap, err
	}

	return delegate, resourceMap, nil
}
*/

/*

	networks, err := GetNetworkSelectionAnnotation(pod)
	if networks != nil {
		delegates, err := ProcessNetworkSelection(clientInfo, pod, networks, conf, resourceMap)

		if err != nil {
			if _, ok := err.(*NoK8sNetworkError); ok {
				return 0, clientInfo, nil
			}
			return 0, nil, logging.Errorf("TryLoadPodDelegates: error in getting k8s network for pod: %v", err)
		}



*/

func mutatePod(w http.ResponseWriter, r *http.Request) {
	logging.Verbosef("received message on mutate")

	deserializer := codecs.UniversalDeserializer()

	// Parse the AdmissionReview from the http request.
	admissionReviewRequest, err := admissionReviewFromRequest(r, deserializer)
	if err != nil {
		msg := fmt.Sprintf("error getting admission review from request: %v", err)
		logging.Verbosef(msg)
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	// Do server-side validation that we are only dealing with a pod resource. This
	// should also be part of the MutatingWebhookConfiguration in the cluster, but
	// we should verify here before continuing.
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if admissionReviewRequest.Request.Resource != podResource {
		msg := fmt.Sprintf("did not receive pod, got %s", admissionReviewRequest.Request.Resource.Resource)
		logging.Verbosef(msg)
		w.WriteHeader(400)
		w.Write([]byte(msg))
		return
	}

	// Decode the pod from the AdmissionReview.
	rawRequest := admissionReviewRequest.Request.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := deserializer.Decode(rawRequest, nil, &pod); err != nil {
		msg := fmt.Sprintf("error decoding raw pod: %v", err)
		logging.Verbosef(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	// !bang
	var labellist map[string]string
	whereaboutsfound := true
	networks, err := GetNetworkSelectionAnnotation(&pod)
	if networks != nil {
		labellist, err = ProcessNetworkSelection(&pod, networks)
		if err != nil {
			if _, ok := err.(*NoK8sNetworkError); ok {
				whereaboutsfound = false
				logging.Verbosef("no Whereabouts networks found in selection for pod: %v/%v", pod.Namespace, pod.Name)
				// return
			}
		}
		logging.Verbosef("!bang labellist: %v", labellist)
	} else {
		whereaboutsfound = false
	}

	// Create a response that will add a label to the pod if it does
	// not already have a label with the key of "hello". In this case
	// it does not matter what the value is, as long as the key exists.
	admissionResponse := &admissionv1.AdmissionResponse{}
	admissionResponse.Allowed = true

	if whereaboutsfound {

		var patch []map[string]interface{}
		patchType := admissionv1.PatchTypeJSONPatch
		for key, value := range labellist {
			patch = append(patch, map[string]interface{}{
				"op":   "add",
				"path": "/metadata/labels",
				"value": map[string]string{
					key: value,
				},
			})
		}

		logging.Verbosef("!bang patch: %v", patch)

		// Convert the patch to JSON
		patchBytes, err := json.Marshal(patch)
		if err != nil {
			// Handle error
		}

		// Set the patch and patch type in the admission response
		admissionResponse.PatchType = &patchType
		admissionResponse.Patch = patchBytes

	}

	// Construct the response, which is just another AdmissionReview.
	var admissionReviewResponse admissionv1.AdmissionReview
	admissionReviewResponse.Response = admissionResponse
	admissionReviewResponse.SetGroupVersionKind(admissionReviewRequest.GroupVersionKind())
	admissionReviewResponse.Response.UID = admissionReviewRequest.Request.UID

	resp, err := json.Marshal(admissionReviewResponse)
	if err != nil {
		msg := fmt.Sprintf("error marshalling response json: %v", err)
		logging.Verbosef(msg)
		w.WriteHeader(500)
		w.Write([]byte(msg))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// Request represents the necessary info from http.Request to process
type Request struct {
	w    http.ResponseWriter
	r    *http.Request
	done chan bool // To signal when processing is complete
}

// requestChannel to queue incoming requests
var requestChannel = make(chan Request, 250) // Buffer size of 250, adjust as needed

func RunWebhookServer(certFile, keyFile string, port int) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	logging.Verbosef("Starting webhook server")
	http.HandleFunc("/mutate", enqueueRequest)

	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ErrorLog: log.New(os.Stdout, "", 0), // Direct error logs to stdout
	}

	go processRequests() // Start processing requests from the channel

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			logging.Errorf("Webhook server error: %v", err)
		}
	}()

	return nil
}

// enqueueRequest queues the request for processing
func enqueueRequest(w http.ResponseWriter, r *http.Request) {
	done := make(chan bool)
	requestChannel <- Request{w, r, done}
	<-done // Wait for the request to be processed
}

// processRequests processes requests serially from the requestChannel
func processRequests() {
	for req := range requestChannel {
		mutatePod(req.w, req.r) // Process request
		req.done <- true        // Signal completion
	}
}
