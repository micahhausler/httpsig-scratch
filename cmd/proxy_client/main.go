package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/signer"
	"github.com/micahhausler/httpsig-scratch/gh"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))
	slog.SetDefault(logger)
}

// // Define a custom type that wraps the existing Transport
// type customTransportWrapper struct {
// 	Transport http.RoundTripper
// 	TLSConfig *tls.Config
// }

// func (c *customTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
// 	// Get the underlying transport, or use http.DefaultTransport if nil
// 	transport := c.Transport
// 	if transport == nil {
// 		transport = http.DefaultTransport
// 	}

// 	// If the transport is an http.Transport, apply the custom TLS config
// 	if t, ok := transport.(*http.Transport); ok {
// 		// Clone the existing transport to avoid modifying the original
// 		tCopy := t.Clone()
// 		tCopy.TLSClientConfig = c.TLSConfig
// 		return tCopy.RoundTrip(req)
// 	}

// 	// Call the original transport's RoundTrip method for non-http.Transport types
// 	return transport.RoundTrip(req)
// }

func main() {
	keyFile := flag.String("key", "", "path to private key")
	kubeConfig := flag.String("kubeconfig", "./kubeconfig", "path to kubeconfig")
	klog.InitFlags(flag.CommandLine)
	flag.Parse()

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		slog.Error("failed to read key file", "error", err)
		os.Exit(1)
	}

	algorithm, err := gh.NewGHSigner(keyData)
	if err != nil {
		slog.Error("failed to create signer", "error", err)
		os.Exit(1)
	}

	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		// CoveredComponents: []string{
		// 	"@method", "@target-uri", "content-type", "content-length", "content-digest",
		// },
		// CoveredComponents: []string{
		// 	"@method", "@target-uri", "content-type", "content-length", "content-digest",
		// 	"user-agent", "accept",
		// },
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
	})

	baseTransport := http.DefaultTransport.(*http.Transport)
	baseTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		slog.Error("failed to read kubeconfig", "error", err)
		os.Exit(1)
	}
	// strip out auth from kubeconfig
	config = rest.AnonymousClientConfig(config)

	config.Transport = &signer.Transport{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		// CoveredComponents: []string{
		// 	"@method", "@target-uri", "content-type", "content-length", "content-digest",
		// 	"user-agent", "accept",
		// },
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			slog.Debug("signing string", "string", stringToSign)
		},
		BaseTransport: baseTransport,
	}

	// func() {
	// 	uri, _ := url.Parse(config.Host)
	// 	uri.Path = `/version`
	// 	res, err := client.Get(uri.String())
	// 	if err != nil {
	// 		slog.Error("failed to send get request", "error", err)
	// 		return
	// 	}
	// 	resBytes, err := httputil.DumpResponse(res, true)
	// 	if err != nil {
	// 		slog.Error("failed to dump response", "error", err)
	// 		os.Exit(1)
	// 	}
	// 	fmt.Println(string(resBytes))
	// }()

	{
		uri, _ := url.Parse(config.Host)
		uri.Path = `/apis/authentication.k8s.io/v1/selfsubjectreviews`
		data := bytes.NewBuffer(
			[]byte(`{"kind":"SelfSubjectReview","apiVersion":"authentication.k8s.io/v1","metadata":{"creationTimestamp":null},"status":{"userInfo":{}}}`),
		)

		res, err := client.Post(uri.String(), "application/json", data)
		if err != nil {
			slog.Error("failed to send request", "error", err)
			os.Exit(1)
		}

		resBytes, err := httputil.DumpResponse(res, true)
		if err != nil {
			slog.Error("failed to dump response", "error", err)
			os.Exit(1)
		}

		fmt.Println(string(resBytes))
	}

	clientset, err := kubernetes.NewForConfigAndClient(config, client)

	// create the clientset
	// clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("failed to read kubeconfig", "error", err)
		os.Exit(1)
	}

	sar, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(
		context.TODO(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		slog.Error("failed to get self subject review", "error", err)
	}
	data, err := yaml.Marshal(sar)
	if err != nil {
		slog.Error("failed to marshal pods", "error", err)
		os.Exit(1)
	}
	fmt.Println(string(data))

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		slog.Error("failed to list pods", "error", err)
		os.Exit(1)
	}
	data, err = yaml.Marshal(pods)
	if err != nil {
		slog.Error("failed to marshal pods", "error", err)
		os.Exit(1)
	}
	fmt.Println(string(data))

}
