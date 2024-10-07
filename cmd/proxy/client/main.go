package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/common-fate/httpsig"
	"github.com/common-fate/httpsig/signer"
	"github.com/micahhausler/httpsig-scratch/gh"
	"github.com/micahhausler/httpsig-scratch/transport"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

func main() {
	keyFile := flag.String("key", "", "path to GitHub private key")
	kubeConfig := flag.String("kubeconfig", "./kubeconfig", "path to kubeconfig")
	klog.InitFlags(flag.CommandLine)
	flag.Parse()

	keyData, err := os.ReadFile(*keyFile)
	if err != nil {
		klog.Fatal("failed to read key file ", err)
	}

	algorithm, err := gh.NewGHSigner(keyData)
	if err != nil {
		klog.Fatal("failed to create signer ", err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		klog.Fatal("failed to read kubeconfig ", err)
	}
	// strip out any auth from kubeconfig
	config = rest.AnonymousClientConfig(config)

	baseTransport := http.DefaultTransport.(*http.Transport)
	baseTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	tport := &signer.Transport{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		// CoveredComponents: []string{
		// 	"@method", "@target-uri", "content-type", "content-length", "content-digest",
		// 	"user-agent", "accept",
		// },
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			klog.V(4).InfoS("signing string", "string", stringToSign)
		},
		BaseTransport: transport.NewTransportWithFallbackHeaders(baseTransport, http.Header{
			"Content-Type": []string{"application/json"},
		}),
	}

	config.Transport = tport

	// have to set both a client and override the transport, need to debug this and only do one
	client := httpsig.NewClient(httpsig.ClientOpts{
		KeyID: algorithm.KeyID(),
		Tag:   "foo",
		Alg:   algorithm,
		// TODO: Alter for GET requests that don't have content-type/content-length/content-digest
		// CoveredComponents: []string{
		// 	"@method", "@target-uri", "content-type", "content-length", "content-digest",
		// 	"user-agent", "accept",
		// },
		OnDeriveSigningString: func(ctx context.Context, stringToSign string) {
			klog.V(4).InfoS("signing string", "string", stringToSign)
		},
	})
	client.Transport = transport.NewTransportWithFallbackHeaders(client.Transport, http.Header{
		"Content-Type": []string{"application/json"},
	})

	// clientset, err := kubernetes.NewForConfig(config)
	clientset, err := kubernetes.NewForConfigAndClient(config, client)
	if err != nil {
		klog.Fatal("failed to read kubeconfig ", err)
	}

	klog.Info("Creating self subject review, `kubectl auth whoami`")
	sar, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(
		context.TODO(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		klog.ErrorS(err, "failed to get self subject review")
	}
	data, err := yaml.Marshal(sar)
	if err != nil {
		klog.Fatal("failed to marshal pods ", err)
	}
	fmt.Println(string(data))

	pods, err := clientset.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{
		Limit: 2,
	})
	if err != nil {
		klog.Fatal("failed to list pods ", err)
	}
	data, err = yaml.Marshal(pods)
	if err != nil {
		klog.Fatal("failed to marshal pods ", err)
	}
	fmt.Println(string(data))

}
