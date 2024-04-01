package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"k8s.io/client-go/util/workqueue"

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

// ProcessNetworkSelection returns delegatenetconf from net-attach-def annotation in pod
func ProcessNetworkSelection(pod *v1.Pod, networks []*types.NetworkSelectionElement) (map[string]string, string, error) {
	// logging.Debugf("ProcessNetworkSelection: %v, %v", pod, networks)
	cconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", fmt.Errorf("failed to implicitly generate the kubeconfig: %w", err)
	}

	nc, err := netclient.NewForConfig(cconfig)
	if err != nil {
		return nil, "", err
	}

	var uuid string

	labellist := make(map[string]string)
	for idx, net := range networks {
		logging.Verbosef("!bang each ProcessNetworkSelection: %v / %v", net.Namespace, net.Name)
		netattach, err := nc.K8sCniCncfIoV1().NetworkAttachmentDefinitions(net.Namespace).Get(context.TODO(), net.Name, metav1.GetOptions{})
		if err != nil {
			return nil, uuid, err
		}
		logging.Verbosef("!bang ProcessNetworkSelection NET-ATTACH-DEF: %v", netattach)

		// NEXT!
		// We  need to parse the delegate to see if it's from Whereabouts
		if strings.Contains(netattach.Spec.Config, "whereabouts") {

			uuid = generateUUID()
			uuidPath := fmt.Sprintf("%s-%s", "whereabouts", uuid)
			logging.Verbosef("!bang UUID PATH: %v", uuidPath)

			// Then we need to get the IPAM config from within it. Or do we? I don't think we do.
			// Then we need to emulate a CNI ADD...
			ipamConf, _, err := config.LoadIPAMConfig([]byte(netattach.Spec.Config), cniArgs(pod.Namespace, pod.Name))
			if err != nil {
				logging.Errorf("IPAM configuration load failed: %s", err)
				return nil, uuid, err
			}

			k8sipam, err := kubernetes.NewKubernetesIPAM(uuidPath, *ipamConf)
			if err != nil {
				return nil, uuid, logging.Errorf("failed to create Kubernetes IPAM manager: %v", err)
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
				// Replace the '/' character with '-' and ':' with '_'
				cidrString := strings.ReplaceAll(ipNet.String(), "/", "-")
				cidrString = strings.ReplaceAll(cidrString, ":", "_")
				ipsAsString = append(ipsAsString, cidrString)
			}
			ipsList := strings.Join(ipsAsString, ",")

			// Insert entry to the hashList map
			labellist[fmt.Sprintf("whereabouts-%d", idx)] = ipsList

		} else {
			return nil, uuid, &NoK8sNetworkError{"no Whereabouts networks found in selection"}
		}

	}

	return labellist, uuid, nil
}

func cniArgs(podNamespace string, podName string) string {
	return fmt.Sprintf("IgnoreUnknown=1;K8S_POD_NAMESPACE=%s;K8S_POD_NAME=%s", podNamespace, podName)
}

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
	var uuid string
	var labellist map[string]string
	whereaboutsfound := true
	networks, err := GetNetworkSelectionAnnotation(&pod)
	if networks != nil {
		labellist, uuid, err = ProcessNetworkSelection(&pod, networks)
		if err != nil {
			if _, ok := err.(*NoK8sNetworkError); ok {
				whereaboutsfound = false
				logging.Verbosef("no Whereabouts networks found in selection for pod: %v/%v", pod.Namespace, pod.Name)
				// return
			}
		}
		labellist["uuid-whereabouts"] = uuid
		logging.Verbosef("!bang labellist: %v", labellist)
	} else {
		whereaboutsfound = false
	}

	// Stub an admission response.
	admissionResponse := &admissionv1.AdmissionResponse{}
	admissionResponse.Allowed = true

	if whereaboutsfound {

		// bang! commented starting here.
		var patch []map[string]interface{}
		patchType := admissionv1.PatchTypeJSONPatch

		// Assuming `pod` is already decoded from the AdmissionReview request
		labelsExist := len(pod.ObjectMeta.Labels) > 0

		// If no labels exist, initialize them
		if !labelsExist {
			patch = append(patch, map[string]interface{}{
				"op":    "add",
				"path":  "/metadata/labels",
				"value": map[string]string{}, // Initialize as an empty object
			})
		}

		for key, value := range labellist {
			// Encode the label key to handle any characters that aren't allowed in JSON Pointer paths
			escapedKey := strings.Replace(key, "/", "~1", -1) // Escape '/' as '~1' as per JSON Pointer spec
			patch = append(patch, map[string]interface{}{
				"op":    "add",
				"path":  fmt.Sprintf("/metadata/labels/%s", escapedKey),
				"value": value,
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
		// bang! commented ending here.

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
var workQueue workqueue.RateLimitingInterface

func RunWebhookServer(certFile, keyFile string, port int, workQueueIn workqueue.RateLimitingInterface) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	workQueue = workQueueIn

	logging.Verbosef("Starting webhook server")
	http.HandleFunc("/mutate", enqueueRequest)

	server := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		ErrorLog: log.New(os.Stdout, "", 0), // Direct error logs to stdout
	}

	// go processRequests() // Start processing requests from the channel

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			logging.Errorf("Webhook server error: %v", err)
		}
	}()

	return nil
}

// enqueueRequest queues the request for processing
func enqueueRequest(w http.ResponseWriter, r *http.Request) {
	logging.Debugf("!bang enqueueRequest...")
	done := make(chan bool)
	workQueue.Add(Request{w, r, done})
	<-done // Wait for processing to complete
}

// processRequests processes requests serially from the requestChannel
func processRequests() {
	for req := range requestChannel {
		mutatePod(req.w, req.r) // Process request
		req.done <- true        // Signal completion
	}
}

func ProcessSingleRequest(queueItem interface{}) {

	req := queueItem.(Request)
	mutatePod(req.w, req.r) // Process request
	workQueue.Forget(req)
	req.done <- true // Signal completion

}
