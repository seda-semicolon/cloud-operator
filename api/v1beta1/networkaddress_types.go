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

// NetworkAddressSpec defines the desired state of NetworkAddress
type NetworkAddressSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an examplse field of NetworkAddress. Edit networkaddress_types.go to remove/update
	// +kubebuilder:validation:Enum=domain
	Type    string   `json:"type"`
	Address []string `json:"address"`
	// +nullable
	AllowedHTTPPorts *string `json:"allowedHttpPorts,omitempty"`
	// +nullable
	AllowedTLSPorts *string `json:"allowedTlsPorts,omitempty"`
	// +nullable
	AllowedForwardPorts *string `json:"allowedForwardPorts,omitempty"`

	// +kubebuilder:default=true
	ExternalAddress bool `json:"externalDns"`
	// +kubebuilder:default=true
	AllowGateway bool `json:"allowRPI"`
}

// NetworkAddressStatus defines the observed state of NetworkAddress
type NetworkAddressStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// NetworkAddress is the Schema for the networkaddresses API
type NetworkAddress struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkAddressSpec   `json:"spec,omitempty"`
	Status NetworkAddressStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkAddressList contains a list of NetworkAddress
type NetworkAddressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkAddress `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkAddress{}, &NetworkAddressList{})
}
