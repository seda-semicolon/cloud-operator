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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetworkAddressBindingSpec defines the desired state of NetworkAddressBinding
// MAKE WHOLE THING IMMUTABLE!!! except servicename, targerport
type NetworkAddressBindingSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of NetworkAddressBinding. Edit networkaddressbinding_types.go to remove/update
	NetworkAddressGrant string `json:"networkAddress"`
	Address             string `json:"address"`
	ServiceName         string `json:"service"`

	// +kubebuilder:validation:Enum=cloudflare;http;tls-passthrough;port-forward;dns
	ConnectionProvider string `json:"connectionProvider"`

	// +kubebuilder:default=false
	// TODO: wait for project contour impl.
	ProxyProtocol bool `json:"proxyProtocol"`
}

// NetworkAddressBindingStatus defines the observed state of NetworkAddressBinding
type NetworkAddressBindingStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	IsValid bool `json:"valid"`

	// +nullable
	TunnelName *string `json:"tunnelName"`

	// +nullable
	CurrentRouteMapping map[string]string `json:"routeNames"`
	// +nullable
	DNSRecordID *string `json:"recordId"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// NetworkAddressBinding is the Schema for the networkaddressbindings API
type NetworkAddressBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkAddressBindingSpec   `json:"spec,omitempty"`
	Status NetworkAddressBindingStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkAddressBindingList contains a list of NetworkAddressBinding
type NetworkAddressBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkAddressBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkAddressBinding{}, &NetworkAddressBindingList{})
}
