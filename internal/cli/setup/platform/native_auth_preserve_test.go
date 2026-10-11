package platform

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"mcp-runtime/internal/cli/registry"
	"sigs.k8s.io/yaml"
)

func TestNativePlatformSetupPreservesSignerAndPullMode(t *testing.T) {
	for _, component := range []struct {
		deployment, container, file string
		envs                        []corev1.EnvVar
	}{
		{"mcp-platform-api", "platform-api", "../../../../k8s/08-platform-api.yaml", []corev1.EnvVar{
			{Name: "REGISTRY_TOKEN_REALM", Value: "https://platform.example/token"},
			{Name: "REGISTRY_TOKEN_SIGNING_KEY_FILE", Value: "/registry-token-signer/signing.key"},
			{Name: "REGISTRY_TOKEN_SIGNING_CERT_FILE", Value: "/registry-token-signer/signing.crt"},
		}},
		{"mcp-runtime-api", "runtime-api", "../../../../k8s/08-runtime-api.yaml", []corev1.EnvVar{{Name: "MCP_REGISTRY_NATIVE_AUTH", Value: "true"}}},
	} {
		t.Run(component.container, func(t *testing.T) {
			group := int64(65532)
			pod := corev1.PodSpec{Containers: []corev1.Container{{Name: component.container, Image: "old", Env: append(component.envs, corev1.EnvVar{Name: "UNRELATED_OLD_ENV", Value: "drop"})}}}
			if component.container == "platform-api" {
				pod.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "registry-token-signer", MountPath: "/registry-token-signer", ReadOnly: true}}
				pod.Volumes = []corev1.Volume{{Name: "registry-token-signer", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "mcp-registry-token-signer"}}}}
				pod.SecurityContext = &corev1.PodSecurityContext{FSGroup: &group}
			}
			live := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: component.deployment, Namespace: "mcp-platform"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: pod}}}
			cs := fake.NewSimpleClientset(live)
			input, err := os.ReadFile(component.file)
			if err != nil {
				t.Fatal(err)
			}
			output, err := preserveNativePlatformManifest(context.Background(), cs, string(input))
			if err != nil {
				t.Fatal(err)
			}
			var desired appsv1.Deployment
			for _, doc := range strings.Split(output, "---\n") {
				var candidate appsv1.Deployment
				if err := yaml.Unmarshal([]byte(doc), &candidate); err != nil {
					t.Fatal(err)
				}
				if candidate.Kind == "Deployment" && candidate.Name == component.deployment {
					desired = candidate
					break
				}
			}
			found := false
			for _, c := range desired.Spec.Template.Spec.Containers {
				if c.Name != component.container {
					continue
				}
				found = true
				if c.Image == "old" {
					t.Fatal("preservation replaced the requested image")
				}
				for _, want := range component.envs {
					got := false
					for _, env := range c.Env {
						if env.Name == want.Name && env.Value == want.Value {
							got = true
						}
					}
					if !got {
						t.Fatalf("lost native env %s", want.Name)
					}
				}
				for _, env := range c.Env {
					if env.Name == "UNRELATED_OLD_ENV" {
						t.Fatal("preserved unrelated stale env")
					}
				}
				if component.container == "platform-api" {
					if desired.Spec.Template.Spec.SecurityContext.FSGroup == nil || *desired.Spec.Template.Spec.SecurityContext.FSGroup != group {
						t.Fatal("lost signer fsGroup")
					}
					mountFound, volumeFound := false, false
					for _, mount := range c.VolumeMounts {
						if mount.Name == "registry-token-signer" && mount.ReadOnly && mount.MountPath == "/registry-token-signer" {
							mountFound = true
						}
					}
					for _, volume := range desired.Spec.Template.Spec.Volumes {
						if volume.Name == "registry-token-signer" && volume.Secret != nil && volume.Secret.SecretName == "mcp-registry-token-signer" {
							volumeFound = true
						}
					}
					if !mountFound || !volumeFound {
						t.Fatal("lost signer secret mount")
					}
				}
			}
			if !found {
				t.Fatal("missing workload container")
			}
			for _, action := range cs.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("preservation mutated cluster")
				}
			}
		})
	}
}

func TestNativePlatformInspectionFailsClosed(t *testing.T) {
	input := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: mcp-platform-api\n  namespace: mcp-platform\n"
	cs := fake.NewSimpleClientset()
	if _, err := preserveNativePlatformManifest(context.Background(), cs, input); err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	cs.PrependReactor("get", "deployments", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("API unavailable")
	})
	if _, err := preserveNativePlatformManifest(context.Background(), cs, input); err == nil {
		t.Fatal("inspection failure must abort reapplication")
	}
}

func TestClientGoRegistrySetupRetainsBackendAndIngressAuth(t *testing.T) {
	live := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "registry", Namespace: "registry"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "registry", Env: []corev1.EnvVar{{Name: "REGISTRY_AUTH", Value: "token"}}, VolumeMounts: []corev1.VolumeMount{{Name: "registry-token-root", MountPath: "/registry-token-root", ReadOnly: true}}}}, Volumes: []corev1.Volume{{Name: "registry-token-root", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "registry-token-root"}}}}}}}}
	input := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: registry\nspec:\n  template:\n    spec:\n      containers:\n      - name: registry\n        image: registry:2.8.3\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: registry\nspec:\n  type: NodePort\n  ports:\n  - port: 5000\n    nodePort: 30500\n---\napiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: registry\n  annotations:\n    traefik.ingress.kubernetes.io/router.middlewares: registry-admin-auth@file\n"
	rendered, err := mutateRegistryManifest(input, "registry.example.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	output, err := registry.PreserveNativeRegistryManifest(context.Background(), fake.NewSimpleClientset(live), "registry", rendered)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"REGISTRY_AUTH", "token", "registry-token-root", "ClusterIP", "registry-admin-auth@file"} {
		if !strings.Contains(output, want) {
			t.Fatalf("lost %s", want)
		}
	}
	if strings.Contains(output, "nodePort") || strings.Contains(output, "NodePort") {
		t.Fatal("reopened node port")
	}
}
