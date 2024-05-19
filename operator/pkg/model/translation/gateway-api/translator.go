// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"github.com/cilium/cilium/operator/pkg/model/ingestion"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var _ translation.Translator = (*gatewayAPITranslator)(nil)

const (
	ciliumGatewayPrefix = "cilium-gateway-"
	owningGatewayLabel  = "io.cilium.gateway/owning-gateway"
)

type gatewayAPITranslator struct {
	cecTranslator translation.CECTranslator

	hostNetworkEnabled bool
}

func NewTranslator(cecTranslator translation.CECTranslator, hostNetworkEnabled bool) translation.Translator {
	return &gatewayAPITranslator{
		cecTranslator:      cecTranslator,
		hostNetworkEnabled: hostNetworkEnabled,
	}
}

func (t *gatewayAPITranslator) Translate(m *model.Model) (*ciliumv2.CiliumEnvoyConfig, *corev1.Service, *corev1.Endpoints, error) {
	listeners := m.GetListeners()
	if len(listeners) == 0 || len(listeners[0].GetSources()) == 0 {
		return nil, nil, nil, fmt.Errorf("model source can't be empty")
	}

	var source *model.FullyQualifiedResource
	var ports []uint32
	for _, l := range listeners {
		source = &l.GetSources()[0]

		ports = append(ports, l.GetPort())
	}

	if source == nil || source.Name == "" {
		return nil, nil, nil, fmt.Errorf("model source name can't be empty")
	}

	cec, err := t.cecTranslator.Translate(source.Namespace, ciliumGatewayPrefix+source.Name, m)
	if err != nil {
		return nil, nil, nil, err
	}

	// Set the owner reference to the CEC object.
	cec.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: gatewayv1beta1.GroupVersion.String(),
			Kind:       source.Kind,
			Name:       source.Name,
			UID:        types.UID(source.UID),
			Controller: model.AddressOf(true),
		},
	}

	allLabels, allAnnotations := map[string]string{}, map[string]string{}
	// Merge all the labels and annotations from the listeners.
	// Normally, the labels and annotations are the same for all the listeners having same gateway.
	for _, l := range listeners {
		allAnnotations = mergeMap(allAnnotations, l.GetAnnotations())
		allLabels = mergeMap(allLabels, l.GetLabels())
	}

	lbSvc := getService(source, ports, allLabels, allAnnotations)

	if t.hostNetworkEnabled {
		lbSvc.Spec.Type = corev1.ServiceTypeClusterIP
	}

	return cec, lbSvc, getEndpoints(*source), err
}

func getService(resource *model.FullyQualifiedResource, allPorts []uint32, labels, annotations map[string]string) *corev1.Service {
	uniquePorts := map[uint32]struct{}{}
	for _, p := range allPorts {
		uniquePorts[p] = struct{}{}
	}

	ports := make([]corev1.ServicePort, 0, len(uniquePorts))
	for p := range uniquePorts {
		ports = append(ports, corev1.ServicePort{
			Name:     fmt.Sprintf("port-%d", p),
			Port:     int32(p),
			Protocol: corev1.ProtocolTCP,
		})
	}
	// needed to be set to 0.0.0.0/0 because there is a bug in the existing implementation of
	// LoadBalancerSourceRanges and when the sourceRanges is set to a value, then set to null,
	// the service still prevent access. but if the value is 0.0.0.0/0 (instead of null or missing), it works.
	sourceRanges := []string{"0.0.0.0/0", "::/0"}
	if v, ok := annotations[ingestion.ANNOT_SOURCE_RANGE_PREFIX]; ok {
		sourceRanges = strings.Split(v, ",")
	}
	familyPolicy := corev1.IPFamilyPolicySingleStack
	ipfamilies := []corev1.IPFamily{}
	ipfamilies = append(ipfamilies, corev1.IPv4Protocol)

	if v, ok := annotations[ingestion.ANNOT_FAMILY_POLICY]; ok {
		if v == "IPv6" {
			ipfamilies[0] = corev1.IPv6Protocol
		} else {
			familyPolicy = corev1.IPFamilyPolicy(v)
			ipfamilies = append(ipfamilies, corev1.IPv6Protocol)
		}

	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        model.Shorten(ciliumGatewayPrefix + resource.Name),
			Namespace:   resource.Namespace,
			Labels:      mergeMap(map[string]string{owningGatewayLabel: model.Shorten(resource.Name)}, labels),
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       resource.Kind,
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
					Controller: model.AddressOf(true),
				},
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeLoadBalancer,
			Ports:                    ports,
			LoadBalancerSourceRanges: sourceRanges,
			IPFamilies:               ipfamilies,
			IPFamilyPolicy:           &familyPolicy,
		},
	}
}

func getEndpoints(resource model.FullyQualifiedResource) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      model.Shorten(ciliumGatewayPrefix + resource.Name),
			Namespace: resource.Namespace,
			Labels:    map[string]string{owningGatewayLabel: model.Shorten(resource.Name)},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1beta1.GroupVersion.String(),
					Kind:       resource.Kind,
					Name:       resource.Name,
					UID:        types.UID(resource.UID),
					Controller: model.AddressOf(true),
				},
			},
		},
		Subsets: []corev1.EndpointSubset{
			{
				// This dummy endpoint is required as agent refuses to push service entry
				// to the lb map when the service has no backends.
				// Related github issue https://github.com/cilium/cilium/issues/19262
				Addresses: []corev1.EndpointAddress{{IP: "192.192.192.192"}}, // dummy
				Ports:     []corev1.EndpointPort{{Port: 9999}},               // dummy
			},
		},
	}
}

func mergeMap(left, right map[string]string) map[string]string {
	if left == nil {
		return right
	}
	for key, value := range right {
		left[key] = value
	}
	return left
}
