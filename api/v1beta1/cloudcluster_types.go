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

// CloudClusterSpec defines the desired state of CloudCluster
type CloudClusterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of CloudCluster. Edit cloudcluster_types.go to remove/update

	ProjectID string `json:"projectId"`

	// +kubebuilder:default=false
	ExposeNodes bool `json:"exposeNodes"`

	// +kubebuilder:default=false
	ExposeAllNodes bool `json:"exposeAllNodes"`

	// +kubebuilder:default=false
	InternalScheduler bool `json:"internalScheduler"`

	// +kubebuilder:default=false
	AdministrativeCluster bool `json:"admin"`
}

// CloudClusterStatus defines the observed state of CloudCluster
type CloudClusterStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// +nullable
	KeycloakCredential *string `json:"keycloakSecret"`
	// +nullable
	KeycloakClientID *string `json:"keyclockClientId"`

	// +nullable
	ClusterName *string `json:"clusterName"`

	AddressName *string `json:"addressName"`
	BindingName *string `json:"bindingName"`
}

//+kubebuilder:object:generate=true
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// CloudCluster is the Schema for the cloudclusters API
type CloudCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CloudClusterSpec   `json:"spec,omitempty"`
	Status CloudClusterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CloudClusterList contains a list of CloudCluster
type CloudClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CloudCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CloudCluster{}, &CloudClusterList{})
}
