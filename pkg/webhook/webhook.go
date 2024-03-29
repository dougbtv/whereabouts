package webhook

import (
	"context"
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
	"github.com/k8snetworkplumbingwg/whereabouts/pkg/logging"
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

// GetPodNetwork gets net-attach-def annotation from pod
func GetPodNetwork(pod *v1.Pod) ([]*types.NetworkSelectionElement, error) {
	// logging.Debugf("GetPodNetwork: %v", pod)

	netAnnot := pod.Annotations[networkAttachmentAnnot]
	defaultNamespace := pod.ObjectMeta.Namespace

	if len(netAnnot) == 0 {
		return nil, &NoK8sNetworkError{"no kubernetes network found"}
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

// GetNetworkDelegates returns delegatenetconf from net-attach-def annotation in pod
func GetNetworkDelegates(pod *v1.Pod, networks []*types.NetworkSelectionElement) ([]*types.DelegateNetConf, error) {
	// logging.Debugf("GetNetworkDelegates: %v, %v", pod, networks)
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to implicitly generate the kubeconfig: %w", err)
	}

	nc, err := netclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	// Read all network objects referenced by 'networks'
	var delegates []*types.DelegateNetConf

	for _, net := range networks {
		logging.Verbosef("!bang GetNetworkDelegates: %v / %v", net.Namespace, net.Name)
		netattach, err := nc.K8sCniCncfIoV1().NetworkAttachmentDefinitions(net.Namespace).Get(context.TODO(), net.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		logging.Verbosef("!bang GetNetworkDelegates: %v", netattach)
	}

	return delegates, nil
}

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

	networks, err := GetPodNetwork(pod)
	if networks != nil {
		delegates, err := GetNetworkDelegates(clientInfo, pod, networks, conf, resourceMap)

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
	networks, err := GetPodNetwork(&pod)
	if networks != nil {
		_, err = GetNetworkDelegates(&pod, networks)
	}

	// Create a response that will add a label to the pod if it does
	// not already have a label with the key of "hello". In this case
	// it does not matter what the value is, as long as the key exists.
	admissionResponse := &admissionv1.AdmissionResponse{}
	var patch string
	patchType := admissionv1.PatchTypeJSONPatch
	if _, ok := pod.Labels["hello"]; !ok {
		patch = `[{"op":"add","path":"/metadata/labels","value":{"hello":"world"}}]`
	}

	admissionResponse.Allowed = true
	if patch != "" {
		admissionResponse.PatchType = &patchType
		admissionResponse.Patch = []byte(patch)
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

func RunWebhookServer(certFile, keyFile string, port int) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	logging.Verbosef("Starting webhook server")
	http.HandleFunc("/mutate", mutatePod)
	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ErrorLog: log.New(os.Stdout, "", 0), // Direct error logs to stdout
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			logging.Errorf("Webhook server error: %v", err)
		}
	}()

	return nil
}
