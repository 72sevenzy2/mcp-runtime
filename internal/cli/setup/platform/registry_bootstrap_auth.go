package platform

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"mcp-runtime/internal/cli/core"
	"mcp-runtime/pkg/k8sclient"
)

const registryBootstrapAuthName = "registry-bootstrap-auth"

var registryMiddlewareResource = schema.GroupVersionResource{Group: "traefik.io", Version: "v1alpha1", Resource: "middlewares"}

func registryBootstrapMiddleware() string {
	return core.NamespaceRegistry + "-" + registryBootstrapAuthName + "@kubernetescrd"
}

// A fresh platform cannot answer forward-auth before pulling its own image.
// Bootstrap replaces that dependency with a hashed, cluster-held credential;
// it never removes authentication, including if setup is interrupted.
func prepareRegistryBootstrapAuthClientGo(logger *zap.Logger) (bool, error) {
	clients, err := platformKubernetesClients()
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	native, err := registryBackendUsesTokenAuth(ctx, clients, core.NamespaceRegistry)
	if err != nil || native {
		return false, err
	}
	api, err := clients.Clientset.AppsV1().Deployments(core.ComponentNamespace("platform-api")).Get(ctx, "mcp-platform-api", metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("inspect registry auth service: %w", err)
	}
	if err == nil && api.Status.AvailableReplicas > 0 {
		ingress, err := clients.Clientset.NetworkingV1().Ingresses(core.NamespaceRegistry).Get(ctx, core.RegistryServiceName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, value := range strings.Split(ingress.Annotations["traefik.ingress.kubernetes.io/router.middlewares"], ",") {
			if strings.TrimSpace(value) == registryBootstrapMiddleware() {
				return true, nil
			}
		}
		return false, nil
	}
	for _, namespace := range append(imagePullSecretNamespaces(), core.NamespaceMCPRuntime) {
		if err := k8sclient.EnsureNamespace(ctx, clients, namespace, nil); err != nil {
			return false, err
		}
	}
	credentials, err := renderAnalyticsSecretManifestClientGo()
	if err != nil {
		return false, err
	}
	if err := applyManifestYAML(credentials, "", nil); err != nil {
		return false, err
	}
	namespace, name, err := ownedCredential("UI_API_KEY")
	if err != nil {
		return false, err
	}
	password, err := existingSecretDataValueClientGo(namespace, name, "UI_API_KEY")
	if err != nil {
		return false, err
	}
	if err := installRegistryBootstrapAuth(ctx, clients, password); err != nil {
		return false, err
	}
	if logger != nil {
		logger.Info("Registry bootstrap authentication active; anonymous access remains denied")
	}
	return true, nil
}

func installRegistryBootstrapAuth(ctx context.Context, clients *k8sclient.Clients, password string) error {
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("registry bootstrap credential is empty")
	}
	ingress, err := clients.Clientset.NetworkingV1().Ingresses(core.NamespaceRegistry).Get(ctx, core.RegistryServiceName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("inspect registry bootstrap ingress: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash registry bootstrap credential: %w", err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: registryBootstrapAuthName, Namespace: core.NamespaceRegistry, Labels: map[string]string{"app.kubernetes.io/managed-by": "mcp-runtime", "mcpruntime.org/registry-auth": "bootstrap"}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"users": []byte("platform-service:" + string(hash) + "\n")}}
	if _, err := clients.Clientset.CoreV1().Secrets(core.NamespaceRegistry).Create(ctx, secret, metav1.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		existing, getErr := clients.Clientset.CoreV1().Secrets(core.NamespaceRegistry).Get(ctx, secret.Name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		secret.ResourceVersion = existing.ResourceVersion
		if _, err := clients.Clientset.CoreV1().Secrets(core.NamespaceRegistry).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	middleware := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "traefik.io/v1alpha1", "kind": "Middleware",
		"metadata": map[string]any{"name": registryBootstrapAuthName, "namespace": core.NamespaceRegistry, "labels": map[string]any{"app.kubernetes.io/managed-by": "mcp-runtime"}},
		"spec":     map[string]any{"basicAuth": map[string]any{"secret": registryBootstrapAuthName, "realm": "mcp-runtime-registry-bootstrap"}},
	}}
	resource := clients.Dynamic.Resource(registryMiddlewareResource).Namespace(core.NamespaceRegistry)
	if _, err := resource.Create(ctx, middleware, metav1.CreateOptions{}); apierrors.IsAlreadyExists(err) {
		existing, getErr := resource.Get(ctx, middleware.GetName(), metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		middleware.SetResourceVersion(existing.GetResourceVersion())
		if _, err := resource.Update(ctx, middleware, metav1.UpdateOptions{}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Restricted CRD providers must watch the namespace containing this middleware.
	deployments, err := clients.Clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, deployment := range deployments.Items {
		if deployment.Name != "traefik" {
			continue
		}
		changed := false
		for i := range deployment.Spec.Template.Spec.Containers {
			container := &deployment.Spec.Template.Spec.Containers[i]
			const prefix = "--providers.kubernetescrd.namespaces="
			for j, arg := range container.Args {
				if !strings.HasPrefix(arg, prefix) {
					continue
				}
				values := strings.Split(strings.TrimPrefix(arg, prefix), ",")
				found := false
				for _, value := range values {
					if value == core.NamespaceRegistry || value == "" {
						found = true
					}
				}
				if !found {
					container.Args[j] = arg + "," + core.NamespaceRegistry
					changed = true
				}
			}
		}
		if changed {
			if _, err := clients.Clientset.AppsV1().Deployments(deployment.Namespace).Update(ctx, &deployment, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}
	if ingress.Annotations == nil {
		ingress.Annotations = map[string]string{}
	}
	key := "traefik.ingress.kubernetes.io/router.middlewares"
	ingress.Annotations[key] = registryAuthMiddlewareList(ingress.Annotations[key], registryBootstrapMiddleware())
	_, err = clients.Clientset.NetworkingV1().Ingresses(core.NamespaceRegistry).Update(ctx, ingress, metav1.UpdateOptions{})
	return err
}

func finalizeRegistryBootstrapAuthClientGo(_ *zap.Logger) error {
	clients, err := platformKubernetesClients()
	if err != nil {
		return err
	}
	ctx := context.Background()
	api, err := clients.Clientset.AppsV1().Deployments(core.ComponentNamespace("platform-api")).Get(ctx, "mcp-platform-api", metav1.GetOptions{})
	if err != nil {
		return err
	}
	if api.Status.AvailableReplicas < 1 {
		return fmt.Errorf("platform-api is not ready; retaining registry bootstrap authentication")
	}
	ingress, err := clients.Clientset.NetworkingV1().Ingresses(core.NamespaceRegistry).Get(ctx, core.RegistryServiceName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ingress.Annotations == nil {
		ingress.Annotations = map[string]string{}
	}
	key := "traefik.ingress.kubernetes.io/router.middlewares"
	ingress.Annotations[key] = registryAuthMiddlewareList(ingress.Annotations[key], registryAdminAuthMiddleware)
	_, err = clients.Clientset.NetworkingV1().Ingresses(core.NamespaceRegistry).Update(ctx, ingress, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	if err := clients.Dynamic.Resource(registryMiddlewareResource).Namespace(core.NamespaceRegistry).Delete(ctx, registryBootstrapAuthName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err := clients.Clientset.CoreV1().Secrets(core.NamespaceRegistry).Delete(ctx, registryBootstrapAuthName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func registryAuthMiddlewareList(current, auth string) string {
	values := []string{auth}
	for _, value := range strings.Split(current, ",") {
		value = strings.TrimSpace(value)
		if value != "" && value != registryAdminAuthMiddleware && value != registryBootstrapMiddleware() {
			values = append(values, value)
		}
	}
	return strings.Join(values, ",")
}

type registryBootstrapAuthStep struct{}

func (registryBootstrapAuthStep) Name() string { return "registry-bootstrap-auth" }
func (registryBootstrapAuthStep) Run(logger *zap.Logger, deps SetupDeps, ctx *SetupContext) error {
	active, err := deps.PrepareRegistryBootstrapAuth(logger)
	ctx.RegistryBootstrapAuth = active
	return err
}

type registryBootstrapFinalizeStep struct{}

func (registryBootstrapFinalizeStep) Name() string { return "registry-bootstrap-finalize" }
func (registryBootstrapFinalizeStep) Run(logger *zap.Logger, deps SetupDeps, ctx *SetupContext) error {
	if !ctx.RegistryBootstrapAuth {
		return nil
	}
	return deps.FinalizeRegistryBootstrapAuth(logger)
}
