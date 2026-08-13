package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/micahhausler/httpsig-scratch/gh"
	"github.com/micahhausler/httpsig/client"
	"github.com/micahhausler/httpsig/sigconfig"
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

	signer, err := gh.NewGHSigner(keyData)
	if err != nil {
		klog.Fatal("failed to create signer ", err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		klog.Fatal("failed to read kubeconfig ", err)
	}
	// strip out any auth from kubeconfig
	config = rest.AnonymousClientConfig(config)

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// default coverage is @method and @target-uri; the body is bound with
	// a Content-Digest header whenever a request has one
	profile := sigconfig.SigningProfile{
		KeyID:      signer.KeyID(),
		Tag:        "foo",
		TTL:        sigconfig.Duration(5 * time.Minute),
		IncludeAlg: true,
	}
	rt, err := client.NewTransport(baseTransport, signer, profile)
	if err != nil {
		klog.Fatal("failed to create signing transport ", err)
	}
	config.Transport = rt

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatal("failed to create client ", err)
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
