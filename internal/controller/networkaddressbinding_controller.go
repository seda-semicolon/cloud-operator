/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"os"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cloudflareoperatorv1beta1 "github.com/adyanth/cloudflare-operator/api/v1alpha1"
	"github.com/cloudflare/cloudflare-go"
	cloudv1beta1 "seda.club/cloud/api/v1beta1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// NetworkAddressBindingReconciler reconciles a NetworkAddressBinding object
type NetworkAddressBindingReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=networking.cfargotunnel.com,resources=tunnelbinding,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.cfargotunnel.com,resources=tunnelbinding/status,verbs=get

func (r *NetworkAddressBindingReconciler) CheckDomainValidity(ctx context.Context,
	networkAddressBinding *cloudv1beta1.NetworkAddressBinding,
	networkAddress *cloudv1beta1.NetworkAddress,
	allowWildcard bool) {
	if !allowWildcard && strings.Contains(networkAddressBinding.Spec.Address, "*") {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Address", "Wildcard Address is not available for current type : "+networkAddressBinding.Spec.Address)
		return
	}

	var grant = strings.Split(networkAddress.Spec.Address, ".")
	var binding = strings.Split(networkAddressBinding.Spec.Address, ".")
	if len(grant) > len(binding) {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Address", networkAddressBinding.Spec.Address+" is not part of "+networkAddress.Spec.Address)
		return
	}
	if grant[0] != "**" && len(grant) != len(binding) {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Address", networkAddressBinding.Spec.Address+" is not part of "+networkAddress.Spec.Address)
		return
	}

	for i := 0; i < len(grant); i++ {
		if grant[-i] == "*" {
			continue
		}
		if grant[-i] == "**" {
			break
		}
		if grant[-i] != binding[-i] {
			networkAddressBinding.Status.IsValid = false
			r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Address", networkAddressBinding.Spec.Address+" is not part of "+networkAddress.Spec.Address)
			return
		}
	}
	return
}

type PortFilter func(v1.ServicePort) bool

func (r *NetworkAddressBindingReconciler) CheckPortValidity(ctx context.Context,
	networkAddressBinding *cloudv1beta1.NetworkAddressBinding,
	targetService *v1.Service,
	portstr *string,
	filter PortFilter,
) error {
	if portstr == nil {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Provider", "opening port is not available for networkaddress")
		return nil
	}
	ports := strings.Split(*portstr, ",")

	stuff := map[int]bool{}

	for _, v := range targetService.Spec.Ports {
		if filter(v) {
			stuff[int(v.Port)] = true
		}
	}

	for _, v := range ports {
		if strings.ContainsAny(v, "-") {
			rangePort := strings.Split(v, "-")
			fromPort, err := strconv.Atoi(rangePort[0])
			if err != nil {
				r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Port", v+" is not number")
				return err
			}
			toPort, err := strconv.Atoi(rangePort[1])
			if err != nil {
				r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Port", v+" is not number")
				return err
			}

			for key, _ := range stuff {
				if fromPort <= key && key <= toPort {
					stuff[key] = false
				}
			}

		} else {
			i, err := strconv.Atoi(v)
			if err != nil {
				r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Port", v+" is not number")
				return err
			}
			stuff[i] = false
		}
	}

	for k, val := range stuff {
		if val {
			networkAddressBinding.Status.IsValid = false
			r.Recorder.Event(networkAddressBinding, "Warning", "Invalid Port", strconv.Itoa(k)+" is not defined in NetworkAddress")
			return nil
		}
	}
	return nil
}

func (r *NetworkAddressBindingReconciler) CleanupCloudflare(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding) error {
	var log = log.FromContext(ctx)
	if networkAddressBinding.Status.TunnelName != nil {
		var binding cloudflareoperatorv1beta1.TunnelBinding
		if err := r.Client.Get(ctx, types.NamespacedName{Name: *networkAddressBinding.Status.TunnelName, Namespace: networkAddressBinding.Namespace}, &binding); err != nil {
			if !errors.IsNotFound(err) {
				log.Error(err, "An error occured while cleaning up cloudflare; Getting tunnel binding "+*networkAddressBinding.Status.TunnelName)
				return err
			}
		} else {
			if err := r.Client.Delete(ctx, &binding); err != nil {
				log.Error(err, "An error occured while deleting tunnel binding: "+binding.Name+" in "+binding.Namespace)
				return err
			}
			r.Recorder.Event(networkAddressBinding, "Normal", "TunnelBinding", "Tunnel binding deleted: "+*networkAddressBinding.Status.TunnelName)
		}
		networkAddressBinding.Status.TunnelName = nil
	}
	return nil
}

func (r *NetworkAddressBindingReconciler) ReconcileCloudflare(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, networkAddress *cloudv1beta1.NetworkAddress, service *v1.Service) error {
	networkAddressBinding.Status.IsValid = true
	if !networkAddress.Spec.ExternalAddress {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid ConnectionProvider", "External DNS Access disabled")
	}
	r.CheckDomainValidity(ctx, networkAddressBinding, networkAddress, false)

	if !networkAddressBinding.Status.IsValid {
		return r.CleanupCloudflare(ctx, networkAddressBinding)
	}

	// ONLY SUPPORTS 1 LV DEEP.... welp

	var log = log.FromContext(ctx)
	if networkAddressBinding.Status.TunnelName == nil {
		binding := cloudflareoperatorv1beta1.TunnelBinding{
			TunnelRef: cloudflareoperatorv1beta1.TunnelRef{
				Kind:              "ClusterTunnel",
				Name:              "sedaclub-tunnel",
				DisableDNSUpdates: false,
			},
			Subjects: []cloudflareoperatorv1beta1.TunnelBindingSubject{
				{
					Kind: "Service",
					Name: service.Name,
					Spec: cloudflareoperatorv1beta1.TunnelBindingSubjectSpec{
						Fqdn: networkAddress.Spec.Address,
					},
				},
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkAddressBinding.Name,
				Namespace: networkAddress.Namespace,
			},
		}
		if err := r.Client.Create(ctx, &binding); err != nil {
			log.Error(err, "An error occured while creating tunnel binding for "+networkAddressBinding.Name)
			return err
		}
		r.Recorder.Event(networkAddressBinding, "Normal", "TunnelBinding", "Tunnel binding created: "+networkAddressBinding.Name)
		networkAddressBinding.Status.TunnelName = &networkAddressBinding.Name
	} else {
		var binding cloudflareoperatorv1beta1.TunnelBinding
		if err := r.Client.Get(ctx, types.NamespacedName{Name: *networkAddressBinding.Status.TunnelName, Namespace: networkAddressBinding.Namespace}, &binding); err != nil {
			if errors.IsNotFound(err) {
				networkAddressBinding.Status.TunnelName = nil
				return err
			} else {
				log.Error(err, "An error occured while getting tunnel binding for "+*networkAddressBinding.Status.TunnelName)
				return err
			}
		}
		binding.TunnelRef = cloudflareoperatorv1beta1.TunnelRef{
			Kind:              "ClusterTunnel",
			Name:              "sedaclub-tunnel",
			DisableDNSUpdates: false,
		}
		binding.Subjects = []cloudflareoperatorv1beta1.TunnelBindingSubject{
			{
				Kind: "Service",
				Name: service.Name,
				Spec: cloudflareoperatorv1beta1.TunnelBindingSubjectSpec{
					Fqdn: networkAddressBinding.Spec.Address,
				},
			},
		}

		if err := r.Client.Update(ctx, &binding); err != nil {
			log.Error(err, "An error occured while updating tunnel binding for "+networkAddressBinding.Name)
			return err
		}
	}
	return nil
}

func cleanUpGatewayAPI[K any, PK interface {
	*K
	client.Object
}](r *NetworkAddressBindingReconciler, ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding) error {
	for key, value := range networkAddressBinding.Status.CurrentRouteMapping {
		var a K
		if err := r.Get(ctx, types.NamespacedName{
			Name:      value,
			Namespace: networkAddressBinding.Namespace,
		}, PK(&a)); err != nil {
			if !errors.IsNotFound(err) {
				return err
			}
		} else {
			if err := r.Delete(ctx, PK(&a)); err != nil {
				if !errors.IsNotFound(err) {
					// continue;
					return err
				}
			}
		}
		delete(networkAddressBinding.Status.CurrentRouteMapping, key)
	}
	return nil
}

type WeirdObject[K any] interface {
	metav1.Object
	runtime.Object
	*K
}
type CopyFunction func()

func syncGatewayAPI[O any, K interface {
	metav1.Object
	runtime.Object
	*O
}](r *NetworkAddressBindingReconciler,
	ctx context.Context,
	networkAddressBinding *cloudv1beta1.NetworkAddressBinding,
	target map[string]K,
	copyutil func(K, K),
	namegetter func(K) string) (map[string]string, error) {
	updatedResources := map[string]string{}
	for key, value := range networkAddressBinding.Status.CurrentRouteMapping {
		var route O
		if err := r.Get(ctx, types.NamespacedName{Name: value, Namespace: networkAddressBinding.Namespace}, K(&route)); err != nil {
			if !errors.IsNotFound(err) {
				return updatedResources, err
			}
		} else {
			if val, exist := target[key]; exist {
				copyutil(K(&route), val)
				if err := r.Update(ctx, K(&route)); err != nil {
					return updatedResources, err
				}
				updatedResources[key] = value
			} else {
				if err := r.Delete(ctx, K(&route)); err != nil {
					return updatedResources, err
				}
			}
			delete(target, key)
		}
	}
	for key, value := range target {
		var hopefulyItDoesntExist O
		if err := r.Get(ctx, types.NamespacedName{Name: namegetter(value), Namespace: networkAddressBinding.Namespace}, K(&hopefulyItDoesntExist)); err == nil {
			copyutil(&hopefulyItDoesntExist, value)
			if err := r.Update(ctx, K(&hopefulyItDoesntExist)); err != nil {
				return updatedResources, err
			}
		} else {
			if err := r.Create(ctx, value); err != nil {
				return updatedResources, err
			}
		}
		updatedResources[key] = namegetter(value)
	}
	return updatedResources, nil
}

//+kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=tcproute;tlsroute;httproute,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=tcproute/status;tlsroute/status;httproute/status,verbs=get

func (r *NetworkAddressBindingReconciler) ReconcileHTTP(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, networkAddress *cloudv1beta1.NetworkAddress, service *v1.Service) error {
	networkAddressBinding.Status.IsValid = true

	if !networkAddress.Spec.AllowGateway {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid ConnectionProvider", "External Gateway Access disabled")
	}

	r.CheckDomainValidity(ctx, networkAddressBinding, networkAddress, false)

	if err := r.CheckPortValidity(ctx, networkAddressBinding, service, networkAddress.Spec.AllowedHTTPPorts, func(port v1.ServicePort) bool {
		return strings.HasPrefix(port.Name, "http")
	}); err != nil {
		return err
	}

	if !networkAddressBinding.Status.IsValid {
		return cleanUpGatewayAPI[gatewayapiv1alpha2.HTTPRoute](r, ctx, networkAddressBinding)
	}

	// CREATE INGRESS OBJECT.
	namespace := gatewayapiv1alpha2.Namespace("projectcontour")

	toBe := map[string]*gatewayapiv1alpha2.HTTPRoute{}

	for _, port := range service.Spec.Ports {
		if !strings.HasPrefix(port.Name, "http") {
			continue
		}
		portNum := gatewayapiv1alpha2.PortNumber(port.Port)

		route := gatewayapiv1alpha2.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkAddressBinding.Name + "-" + port.Name,
				Namespace: networkAddressBinding.Namespace,
			},
			Spec: gatewayapiv1alpha2.HTTPRouteSpec{
				CommonRouteSpec: gatewayapiv1alpha2.CommonRouteSpec{
					ParentRefs: []gatewayapiv1alpha2.ParentReference{
						{
							Name:      "external-gateway",
							Namespace: &namespace,
							Port:      &portNum,
						},
					},
				},
				Hostnames: []gatewayapiv1alpha2.Hostname{
					gatewayapiv1alpha2.Hostname(networkAddressBinding.Spec.Address),
				},
				Rules: []gatewayapiv1alpha2.HTTPRouteRule{
					{
						BackendRefs: []gatewayapiv1alpha2.HTTPBackendRef{
							{
								BackendRef: gatewayapiv1alpha2.BackendRef{
									BackendObjectReference: gatewayapiv1alpha2.BackendObjectReference{
										Name: gatewayapiv1alpha2.ObjectName(networkAddressBinding.Spec.ServiceName),
										Port: &portNum,
									},
								},
							},
						},
					},
				},
			},
		}
		toBe[port.Name] = &route
	}

	updatedResources, err := syncGatewayAPI[gatewayapiv1alpha2.HTTPRoute, *gatewayapiv1alpha2.HTTPRoute](r, ctx, networkAddressBinding, toBe, func(target *gatewayapiv1alpha2.HTTPRoute, from *gatewayapiv1alpha2.HTTPRoute) {
		target.Spec = from.Spec
	}, func(h *gatewayapiv1alpha2.HTTPRoute) string { return h.Name })
	networkAddressBinding.Status.CurrentRouteMapping = updatedResources
	if err != nil {
		return err
	}

	return addCNameRecord(ctx, networkAddressBinding, "external.seda.club")
}
func (r *NetworkAddressBindingReconciler) ReconcilePortForward(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, networkAddress *cloudv1beta1.NetworkAddress, service *v1.Service) error {
	networkAddressBinding.Status.IsValid = true

	if !networkAddress.Spec.AllowGateway {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid ConnectionProvider", "External Gateway Access disabled")
	}

	r.CheckDomainValidity(ctx, networkAddressBinding, networkAddress, false)

	if err := r.CheckPortValidity(ctx, networkAddressBinding, service, networkAddress.Spec.AllowedForwardPorts, func(port v1.ServicePort) bool {
		return strings.HasPrefix(port.Name, "tcp")
	}); err != nil {
		return err
	}

	if !networkAddressBinding.Status.IsValid {
		return cleanUpGatewayAPI[gatewayapiv1alpha2.TCPRoute](r, ctx, networkAddressBinding)
	}

	// CREATE INGRESS OBJECT.
	namespace := gatewayapiv1alpha2.Namespace("projectcontour")

	toBe := map[string]*gatewayapiv1alpha2.TCPRoute{}

	for _, port := range service.Spec.Ports {
		if !strings.HasPrefix(port.Name, "tcp") {
			continue
		}
		portNum := gatewayapiv1alpha2.PortNumber(port.Port)

		route := gatewayapiv1alpha2.TCPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkAddressBinding.Name + "-" + port.Name,
				Namespace: networkAddressBinding.Namespace,
			},
			Spec: gatewayapiv1alpha2.TCPRouteSpec{
				CommonRouteSpec: gatewayapiv1alpha2.CommonRouteSpec{
					ParentRefs: []gatewayapiv1alpha2.ParentReference{
						{
							Name:      "external-gateway",
							Namespace: &namespace,
							Port:      &portNum,
						},
					},
				},
				Rules: []gatewayapiv1alpha2.TCPRouteRule{
					{
						BackendRefs: []gatewayapiv1alpha2.BackendRef{
							{
								BackendObjectReference: gatewayapiv1alpha2.BackendObjectReference{
									Name: gatewayapiv1alpha2.ObjectName(networkAddressBinding.Spec.ServiceName),
									Port: &portNum,
								},
							},
						},
					},
				},
			},
		}
		toBe[port.Name] = &route
	}

	updatedResources, err := syncGatewayAPI[gatewayapiv1alpha2.TCPRoute, *gatewayapiv1alpha2.TCPRoute](r, ctx, networkAddressBinding, toBe, func(target *gatewayapiv1alpha2.TCPRoute, from *gatewayapiv1alpha2.TCPRoute) {
		target.Spec = from.Spec
	}, func(h *gatewayapiv1alpha2.TCPRoute) string { return h.Name })
	networkAddressBinding.Status.CurrentRouteMapping = updatedResources
	if err != nil {
		return err
	}

	return addCNameRecord(ctx, networkAddressBinding, "external.seda.club")
}
func (r *NetworkAddressBindingReconciler) ReconcileTLSPassthrough(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, networkAddress *cloudv1beta1.NetworkAddress, service *v1.Service) error {
	networkAddressBinding.Status.IsValid = true

	if !networkAddress.Spec.AllowGateway {
		networkAddressBinding.Status.IsValid = false
		r.Recorder.Event(networkAddressBinding, "Warning", "Invalid ConnectionProvider", "External Gateway Access disabled")
	}

	r.CheckDomainValidity(ctx, networkAddressBinding, networkAddress, false)

	if err := r.CheckPortValidity(ctx, networkAddressBinding, service, networkAddress.Spec.AllowedTLSPorts, func(port v1.ServicePort) bool {
		return strings.HasPrefix(port.Name, "tls") || strings.HasPrefix(port.Name, "https")
	}); err != nil {
		return err
	}

	if !networkAddressBinding.Status.IsValid {
		return cleanUpGatewayAPI[gatewayapiv1alpha2.TLSRoute](r, ctx, networkAddressBinding)
	}

	// CREATE INGRESS OBJECT.
	namespace := gatewayapiv1alpha2.Namespace("projectcontour")

	toBe := map[string]*gatewayapiv1alpha2.TLSRoute{}

	for _, port := range service.Spec.Ports {
		if !strings.HasPrefix(port.Name, "tls") || strings.HasPrefix(port.Name, "https") {
			continue
		}
		portNum := gatewayapiv1alpha2.PortNumber(port.Port)

		route := gatewayapiv1alpha2.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkAddressBinding.Name + "-" + port.Name,
				Namespace: networkAddressBinding.Namespace,
			},
			Spec: gatewayapiv1alpha2.TLSRouteSpec{
				CommonRouteSpec: gatewayapiv1alpha2.CommonRouteSpec{
					ParentRefs: []gatewayapiv1alpha2.ParentReference{
						{
							Name:      "external-gateway",
							Namespace: &namespace,
							Port:      &portNum,
						},
					},
				},
				Hostnames: []gatewayapiv1alpha2.Hostname{
					gatewayapiv1alpha2.Hostname(networkAddressBinding.Spec.Address),
				},
				Rules: []gatewayapiv1alpha2.TLSRouteRule{
					{
						BackendRefs: []gatewayapiv1alpha2.BackendRef{
							{
								BackendObjectReference: gatewayapiv1alpha2.BackendObjectReference{
									Name: gatewayapiv1alpha2.ObjectName(networkAddressBinding.Spec.ServiceName),
									Port: &portNum,
								},
							},
						},
					},
				},
			},
		}
		toBe[port.Name] = &route
	}

	updatedResources, err := syncGatewayAPI[gatewayapiv1alpha2.TLSRoute, *gatewayapiv1alpha2.TLSRoute](r, ctx, networkAddressBinding, toBe, func(target *gatewayapiv1alpha2.TLSRoute, from *gatewayapiv1alpha2.TLSRoute) {
		target.Spec = from.Spec
	}, func(h *gatewayapiv1alpha2.TLSRoute) string { return h.Name })
	networkAddressBinding.Status.CurrentRouteMapping = updatedResources
	if err != nil {
		return err
	}

	return addCNameRecord(ctx, networkAddressBinding, "external.seda.club")
}

func addCNameRecord(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, cname string) error {
	if networkAddressBinding.Status.DNSRecordID != nil {
		return nil
	}

	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	falseVal := false
	record, err := api.CreateDNSRecord(ctx,
		&cloudflare.ResourceContainer{
			Level:      cloudflare.ZoneRouteLevel,
			Identifier: os.Getenv("CLOUDFLARE_ZONE_ID"),
			Type:       "zone",
		},
		cloudflare.CreateDNSRecordParams{
			Name:    networkAddressBinding.Spec.Address,
			Content: cname,
			Type:    "CNAME",
			Proxied: &falseVal,
			Comment: "From " + networkAddressBinding.Namespace + "/" + networkAddressBinding.Name,
		},
	)
	if err != nil {
		return err
	}
	networkAddressBinding.Status.DNSRecordID = &record.ID
	return nil
}
func deleteCNameRecord(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding) error {
	if networkAddressBinding.Status.DNSRecordID == nil {
		return nil
	}

	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	err = api.DeleteDNSRecord(ctx,
		&cloudflare.ResourceContainer{
			Level:      cloudflare.ZoneRouteLevel,
			Identifier: os.Getenv("CLOUDFLARE_ZONE_ID"),
			Type:       "zone",
		},
		*networkAddressBinding.Status.DNSRecordID,
	)
	if err != nil {
		return err
	}
	networkAddressBinding.Status.DNSRecordID = nil
	return nil
}

func (r *NetworkAddressBindingReconciler) ReconcileDNS(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, networkAddress *cloudv1beta1.NetworkAddress, service *v1.Service) error {
	networkAddressBinding.Status.IsValid = true

	r.CheckDomainValidity(ctx, networkAddressBinding, networkAddress, false)

	if !networkAddressBinding.Status.IsValid {
		return nil
	}

	if len(service.Status.LoadBalancer.Ingress) > 0 {
		return upsertARecord(ctx, networkAddressBinding, service.Status.LoadBalancer.Ingress[0].IP)
	} else {
		return deleteARecord(ctx, networkAddressBinding)
	}
}

func upsertARecord(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding, ip string) error {
	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	falseVal := false

	if networkAddressBinding.Status.DNSRecordID != nil {
		record, err := api.UpdateDNSRecord(ctx,
			&cloudflare.ResourceContainer{
				Level:      cloudflare.ZoneRouteLevel,
				Identifier: os.Getenv("CLOUDFLARE_ZONE_ID"),
				Type:       "zone",
			},
			cloudflare.UpdateDNSRecordParams{
				Name:    networkAddressBinding.Spec.Address,
				Content: ip,
				Type:    "A",
				ID:      *networkAddressBinding.Status.DNSRecordID,
				Proxied: &falseVal,
				Comment: "From " + networkAddressBinding.Namespace + "/" + networkAddressBinding.Name,
			},
		)
		if err != nil {
			return err
		}
		networkAddressBinding.Status.DNSRecordID = &record.ID
	} else {
		record, err := api.CreateDNSRecord(ctx,
			&cloudflare.ResourceContainer{
				Level:      cloudflare.ZoneRouteLevel,
				Identifier: os.Getenv("CLOUDFLARE_ZONE_ID"),
				Type:       "zone",
			},
			cloudflare.CreateDNSRecordParams{
				Name:    networkAddressBinding.Spec.Address,
				Content: ip,
				Type:    "A",
				Proxied: &falseVal,
				Comment: "From " + networkAddressBinding.Namespace + "/" + networkAddressBinding.Name,
			},
		)
		if err != nil {
			return err
		}
		networkAddressBinding.Status.DNSRecordID = &record.ID
	}

	return nil
}
func deleteARecord(ctx context.Context, networkAddressBinding *cloudv1beta1.NetworkAddressBinding) error {
	if networkAddressBinding.Status.DNSRecordID == nil {
		return nil
	}

	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_TOKEN"))
	if err != nil {
		return err
	}
	err = api.DeleteDNSRecord(ctx,
		&cloudflare.ResourceContainer{
			Level:      cloudflare.ZoneRouteLevel,
			Identifier: os.Getenv("CLOUDFLARE_ZONE_ID"),
			Type:       "zone",
		},
		*networkAddressBinding.Status.DNSRecordID,
	)
	if err != nil {
		return err
	}
	networkAddressBinding.Status.DNSRecordID = nil
	return nil
}

//+kubebuilder:rbac:groups=cloud.seda.club,resources=networkaddressbindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cloud.seda.club,resources=networkaddressbindings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cloud.seda.club,resources=networkaddressbindings/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NetworkAddressBinding object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.15.0/pkg/reconcile
func (r *NetworkAddressBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var log = log.FromContext(ctx)

	var networkAddressBinding cloudv1beta1.NetworkAddressBinding

	if err := r.Get(ctx, req.NamespacedName, &networkAddressBinding); err != nil {
		log.Error(err, "An error occured while fetching NAB CR")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// name of our custom finalizer
	myFinalizerName := "cloudcluster.cloud.seda.club/finalizer"

	// examine DeletionTimestamp to determine if object is under deletion
	if networkAddressBinding.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted, so if it does not have our finalizer,
		// then lets add the finalizer and update the object. This is equivalent
		// registering our finalizer.
		if !controllerutil.ContainsFinalizer(&networkAddressBinding, myFinalizerName) {
			controllerutil.AddFinalizer(&networkAddressBinding, myFinalizerName)
			if err := r.Update(ctx, &networkAddressBinding); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// The object is being deleted
		if controllerutil.ContainsFinalizer(&networkAddressBinding, myFinalizerName) {
			// our finalizer is present, so lets handle any external dependency
			var err error
			switch networkAddressBinding.Spec.ConnectionProvider {
			case "cloudflare":
				err = r.CleanupCloudflare(ctx, &networkAddressBinding)
			case "http":
				err = cleanUpGatewayAPI[gatewayapiv1alpha2.HTTPRoute](r, ctx, &networkAddressBinding)
				if err == nil {
					deleteCNameRecord(ctx, &networkAddressBinding)
				}
			case "tls-passthrough":
				err = cleanUpGatewayAPI[gatewayapiv1alpha2.TLSRoute](r, ctx, &networkAddressBinding)
				if err == nil {
					deleteCNameRecord(ctx, &networkAddressBinding)
				}
			case "port-forward":
				err = cleanUpGatewayAPI[gatewayapiv1alpha2.TCPRoute](r, ctx, &networkAddressBinding)
				if err == nil {
					deleteCNameRecord(ctx, &networkAddressBinding)
				}
			case "dns":
				err = deleteARecord(ctx, &networkAddressBinding)
			default:
			}

			if err != nil {
				log.Error(err, "An error occured while cleaning up NetworkAddressBinding CR")
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}

			if err := r.Client.Status().Update(ctx, &networkAddressBinding); err != nil {
				log.Error(err, "An error occured while saving NetworkAddressBinding CR")
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
			if err := r.Client.Get(ctx, req.NamespacedName, &networkAddressBinding); err != nil {
				log.Error(err, "An error occured while fetching NetworkAddressBinding CR")
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}

			// remove our finalizer from the list and update it.
			controllerutil.RemoveFinalizer(&networkAddressBinding, myFinalizerName)
			if err := r.Update(ctx, &networkAddressBinding); err != nil {
				return ctrl.Result{}, err
			}
		}

		// Stop reconciliation as the item is being deleted
		return ctrl.Result{}, nil
	}

	var networkAddress cloudv1beta1.NetworkAddress
	if err := r.Get(ctx, types.NamespacedName{Name: networkAddressBinding.Spec.NetworkAddressGrant, Namespace: networkAddressBinding.Namespace}, &networkAddress); err != nil {
		if errors.IsNotFound(err) {
			networkAddressBinding.Status.IsValid = false
			r.Recorder.Event(&networkAddressBinding, "Warning", "Invalid NetworkAddress", networkAddressBinding.Spec.NetworkAddressGrant+" not found")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		} else {
			return ctrl.Result{}, err
		}
	}

	var service v1.Service
	if err := r.Get(ctx, types.NamespacedName{Name: networkAddressBinding.Spec.ServiceName, Namespace: networkAddressBinding.Namespace}, &service); err != nil {
		if errors.IsNotFound(err) {
			networkAddressBinding.Status.IsValid = false
			r.Recorder.Event(&networkAddressBinding, "Warning", "Invalid Service", networkAddressBinding.Spec.ServiceName+" not found")
			return ctrl.Result{}, client.IgnoreNotFound(err)
		} else {
			return ctrl.Result{}, err
		}
	}
	// cloudflare;http;tls-passthrough;port-forward;external-dns;internal-dns

	provider := networkAddressBinding.Spec.ConnectionProvider
	var err error
	switch provider {
	case "cloudflare":
		err = r.ReconcileCloudflare(ctx, &networkAddressBinding, &networkAddress, &service)
	case "http":
		err = r.ReconcileHTTP(ctx, &networkAddressBinding, &networkAddress, &service)
	case "tls-passthrough":
		err = r.ReconcileTLSPassthrough(ctx, &networkAddressBinding, &networkAddress, &service)
	case "port-forward":
		err = r.ReconcilePortForward(ctx, &networkAddressBinding, &networkAddress, &service)
	case "dns":
		err = r.ReconcileDNS(ctx, &networkAddressBinding, &networkAddress, &service)
	default:
		return ctrl.Result{}, errors.NewInvalid(networkAddressBinding.GroupVersionKind().GroupKind(), "Invalid connection provider", field.ErrorList{
			&field.Error{
				Type:     field.ErrorTypeForbidden,
				Field:    "connection-provider",
				BadValue: provider,
				Detail:   "Invalid value; must be one of cloudflare;http;tls-passthrough;port-forward;dns",
			},
		})
	}
	if err := r.Status().Update(ctx, &networkAddressBinding); err != nil {
		log.Error(err, "An error occurred while updating status")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err != nil {
		log.Error(err, "An error occured while reconciling validity")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkAddressBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cloudv1beta1.NetworkAddressBinding{}).
		Complete(r)
}
