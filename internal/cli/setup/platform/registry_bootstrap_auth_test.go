package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"mcp-runtime/internal/cli/core"
	"mcp-runtime/internal/cli/registry/config"
	setupplan "mcp-runtime/internal/cli/setup/plan"
)

func bootstrapTestIngress() *networkingv1.Ingress {
	return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "registry", Namespace: "registry", Annotations: map[string]string{"traefik.ingress.kubernetes.io/router.middlewares": registryAdminAuthMiddleware + ",rate-limit@file"}}}
}

func TestRegistryBootstrapAuthUsesHashedCredentialAndRetainsGuardOnFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			traefik := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "traefik", Namespace: "traefik"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "traefik", Args: []string{"--providers.kubernetescrd.namespaces=mcp-platform,custom"}}}}}}}
			clients := newPlatformKubernetesTestClients([]runtime.Object{bootstrapTestIngress(), traefik}, nil)
			if fail {
				clients.Dynamic.(interface {
					PrependReactor(string, string, clienttesting.ReactionFunc)
				}).PrependReactor("create", "middlewares", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("API unavailable")
				})
			}
			password := "a-strong-test-bootstrap-credential"
			err := installRegistryBootstrapAuth(context.Background(), clients, password)
			if (err != nil) != fail {
				t.Fatalf("err=%v, failure=%v", err, fail)
			}
			ingress, err := clients.Clientset.NetworkingV1().Ingresses("registry").Get(context.Background(), "registry", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			auth := ingress.Annotations["traefik.ingress.kubernetes.io/router.middlewares"]
			want := registryBootstrapMiddleware()
			if fail {
				want = registryAdminAuthMiddleware
			}
			if !strings.Contains(auth, want) || !strings.Contains(auth, "rate-limit@file") {
				t.Fatalf("lost ingress protection: %s", auth)
			}
			secret, err := clients.Clientset.CoreV1().Secrets("registry").Get(context.Background(), registryBootstrapAuthName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			users := string(secret.Data["users"])
			if strings.Contains(users, password) {
				t.Fatal("stored plaintext bootstrap credential")
			}
			hash := strings.TrimSuffix(strings.TrimPrefix(users, "platform-service:"), "\n")
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
				t.Fatal(err)
			}
			if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("incorrect")); err == nil {
				t.Fatal("accepted incorrect credential")
			}
			if !fail {
				middleware, err := clients.Dynamic.Resource(registryMiddlewareResource).Namespace("registry").Get(context.Background(), registryBootstrapAuthName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if middleware.Object["spec"] == nil {
					t.Fatal("no BasicAuth configuration")
				}
				deployment, _ := clients.Clientset.AppsV1().Deployments("traefik").Get(context.Background(), "traefik", metav1.GetOptions{})
				if deployment.Spec.Template.Spec.Containers[0].Args[0] != "--providers.kubernetescrd.namespaces=mcp-platform,custom,registry" {
					t.Fatal("failed to retain and extend restricted middleware watch")
				}
			}
		})
	}
}

func TestBootstrapFinalizationWaitsForAPIAndRemovesBootstrapSecrets(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(fmt.Sprint(ready), func(t *testing.T) {
			ingress := bootstrapTestIngress()
			ingress.Annotations["traefik.ingress.kubernetes.io/router.middlewares"] = registryBootstrapMiddleware() + ",rate-limit@file"
			api := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "mcp-platform-api", Namespace: core.ComponentNamespace("platform-api")}}
			if ready {
				api.Status.AvailableReplicas = 1
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: registryBootstrapAuthName, Namespace: "registry"}}
			clients := newPlatformKubernetesTestClients([]runtime.Object{ingress, api, secret}, nil)
			swapKubernetesClientsForTest(t, clients)
			if ready {
				active, err := prepareRegistryBootstrapAuthClientGo(zap.NewNop())
				if err != nil || !active {
					t.Fatalf("interrupted bootstrap must be finalized: %v,%v", active, err)
				}
			}
			err := finalizeRegistryBootstrapAuthClientGo(zap.NewNop())
			if (err == nil) != ready {
				t.Fatalf("ready=%v,err=%v", ready, err)
			}
			after, _ := clients.Clientset.NetworkingV1().Ingresses("registry").Get(context.Background(), "registry", metav1.GetOptions{})
			want := registryBootstrapMiddleware()
			if ready {
				want = registryAdminAuthMiddleware
			}
			if !strings.Contains(after.Annotations["traefik.ingress.kubernetes.io/router.middlewares"], want) {
				t.Fatal("lost authentication")
			}
			_, secretErr := clients.Clientset.CoreV1().Secrets("registry").Get(context.Background(), registryBootstrapAuthName, metav1.GetOptions{})
			if (secretErr != nil) != ready {
				t.Fatal("incorrect bootstrap secret lifecycle")
			}
			if ready {
				active, err := prepareRegistryBootstrapAuthClientGo(zap.NewNop())
				if err != nil || active {
					t.Fatalf("ready API should not reinstall bootstrap: %v,%v", active, err)
				}
			}
		})
	}
}

func TestSetupBootstrapPipelineOrderAndFailedBuildKeepsAuthentication(t *testing.T) {
	t.Setenv("MCP_PLATFORM_DOMAIN", "example.com")
	withPlatformIngressHost(t, "platform.example.com")
	ctx := &SetupContext{Plan: setupplan.Plan{TLSEnabled: true, DeployAnalytics: true}}
	steps := buildSetupSteps(ctx)
	names := []string{}
	for _, step := range steps {
		names = append(names, step.Name())
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "registry,registry-bootstrap-auth,operator-image") || !strings.Contains(joined, "analytics-deploy,registry-bootstrap-finalize,verify,registry-native-auth") {
		t.Fatalf("unsafe bootstrap order: %s", joined)
	}
	finalized := false
	deps := SetupDeps{
		OperatorImageFor:              func(*config.ExternalRegistryConfig) string { return "registry.example.com/operator:build" },
		PrepareRegistryBootstrapAuth:  func(*zap.Logger) (bool, error) { return true, nil },
		FinalizeRegistryBootstrapAuth: func(*zap.Logger) error { finalized = true; return nil },
		BuildOperatorImage:            func(string) error { return fmt.Errorf("build failed") },
		ResolvePlatformRegistryURL:    func(*zap.Logger) string { return "registry.example.com" },
	}
	err := runSetupSteps(zap.NewNop(), deps, ctx, []SetupStep{registryBootstrapAuthStep{}, operatorImageStep{}})
	if err == nil || !ctx.RegistryBootstrapAuth || finalized {
		t.Fatal("failed build must leave bootstrap authentication active")
	}
}

func TestNativePullCredentialsSurviveSetup(t *testing.T) {
	original := core.DefaultCLIConfig
	core.DefaultCLIConfig = &core.CLIConfig{RegistryEndpoint: "registry.example.com", RegistryIngressHost: "registry.example.com"}
	t.Cleanup(func() { core.DefaultCLIConfig = original })
	t.Setenv("MCP_REGISTRY_ENDPOINT", "registry.example.com")
	t.Setenv("MCP_REGISTRY_HOST", "registry.example.com")
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: defaultRegistrySecretName, Namespace: "mcp-runtime", Labels: map[string]string{"mcpruntime.org/registry-auth": "pull"}}, Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte("existing-scoped-credential")}}
	native := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "registry", Namespace: "registry"}}
	native.Spec.Template.Spec.Containers = []corev1.Container{{Name: "registry", Env: []corev1.EnvVar{{Name: "REGISTRY_AUTH", Value: "token"}}}}
	clients := newPlatformKubernetesTestClients([]runtime.Object{secret, native}, nil)
	swapKubernetesClientsForTest(t, clients)
	name, err := ensureBundledPublicRegistryPullSecretClientGo("mcp-runtime", []string{"registry.example.com/operator:release"})
	if err != nil || name != defaultRegistrySecretName {
		t.Fatalf("%s,%v", name, err)
	}
	if _, err := ensureBundledPublicRegistryPullSecretClientGo("missing-scope", []string{"registry.example.com/operator:release"}); err == nil {
		t.Fatal("must not fall back to a platform admin credential for native pulls")
	}
	for _, action := range clients.Clientset.(*fake.Clientset).Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("overwrote scoped credential")
		}
	}
}

func TestExistingNativeRegistryDoesNotInstallBootstrapAuth(t *testing.T) {
	live := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "registry", Namespace: "registry"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "registry", Env: []corev1.EnvVar{{Name: "REGISTRY_AUTH", Value: "token"}}}}}}}}
	clients := newPlatformKubernetesTestClients([]runtime.Object{live}, nil)
	swapKubernetesClientsForTest(t, clients)
	active, err := prepareRegistryBootstrapAuthClientGo(zap.NewNop())
	if err != nil || active {
		t.Fatalf("native registry must retain its authentication: %v,%v", active, err)
	}
	for _, action := range clients.Clientset.(*fake.Clientset).Actions() {
		if action.GetVerb() != "get" {
			t.Fatal("mutated native registry bootstrap state")
		}
	}
}

func TestOperatorPublicPullSecretIsPreparedBeforeFirstDeployment(t *testing.T) {
	t.Setenv("MCP_PLATFORM_IMAGE_PULL_SECRET", "")
	t.Setenv("MCP_REGISTRY_PULL_SECRET_NAME", "")
	prepared, deployed := false, false
	image := "registry.example.com/operator:release"
	deps := SetupDeps{
		RestartDeployment: func(string, string) error { return nil },
		EnsureBundledRegistryPullSecret: func(namespace string, images []string) (string, error) {
			if namespace != core.NamespaceMCPRuntime || len(images) != 1 || images[0] != image {
				t.Fatalf("incorrect pull scope: %s,%v", namespace, images)
			}
			prepared = true
			return defaultRegistrySecretName, nil
		},
		DeployOperatorManifests: func(_ *zap.Logger, operatorImage, gatewayImage string, args []string, secret string) error {
			if !prepared || secret != defaultRegistrySecretName {
				t.Fatal("first rollout lacks prepared public pull credential")
			}
			deployed = true
			return nil
		},
	}
	if err := deployOperatorStep(zap.NewNop(), image, "", nil, "", false, nil, deps); err != nil {
		t.Fatal(err)
	}
	if !deployed {
		t.Fatal("deployment not exercised")
	}
}

func TestFreshRegistryReplacesRestoredNativePullCredentialForBootstrap(t *testing.T) {
	original := core.DefaultCLIConfig
	core.DefaultCLIConfig = &core.CLIConfig{RegistryEndpoint: "registry.example.com", RegistryIngressHost: "registry.example.com"}
	t.Cleanup(func() { core.DefaultCLIConfig = original })
	t.Setenv("MCP_REGISTRY_ENDPOINT", "registry.example.com")
	namespace, name, err := ownedCredential("UI_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	owner := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Data: map[string][]byte{"UI_API_KEY": []byte("fresh-bootstrap-test-key")}}
	stale := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: defaultRegistrySecretName, Namespace: "mcp-runtime", Labels: map[string]string{"mcpruntime.org/registry-auth": "pull"}}, Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte("restored-old-scope")}}
	clients := newPlatformKubernetesTestClients([]runtime.Object{owner, stale}, nil)
	swapKubernetesClientsForTest(t, clients)
	if _, err := ensureBundledPublicRegistryPullSecretClientGo("mcp-runtime", []string{"registry.example.com/operator:release"}); err != nil {
		t.Fatal(err)
	}
	after, err := clients.Clientset.CoreV1().Secrets("mcp-runtime").Get(context.Background(), defaultRegistrySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var docker struct {
		Auths map[string]struct{ Username, Password string }
	}
	if err := json.Unmarshal(after.Data[corev1.DockerConfigJsonKey], &docker); err != nil {
		t.Fatal(err)
	}
	entry := docker.Auths["registry.example.com"]
	if entry.Username != "platform-service" || entry.Password != "fresh-bootstrap-test-key" {
		t.Fatal("fresh bootstrap reused a credential tied to the previous registry database")
	}
}
