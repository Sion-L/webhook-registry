package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/Sion-L/admission-validat/pkg"
	admv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {

	// 创建一个ca的配置
	subject := pkix.Name{
		Country:            []string{"CN"},
		Province:           []string{"HuNan"},
		Locality:           []string{"ChangSha"},
		Organization:       []string{"ydzs.io"},
		OrganizationalUnit: []string{"ydzs.io"},
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2022),
		Subject:               subject,
		NotBefore:             time.Now(), // 有限期，从现在到十年后
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// 生成ca的私钥
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 创建自签名的ca证书
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}

	// 编码证书文件
	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		log.Panic(err)
	}

	// 服务端证书配置
	dnsNames := []string{"admission-validat",
		"admission-validat.default",
		"admission-validat.default.svc",
		"admission-validat.default.svc.cluster.local",
	}

	commonName := "admission-validat.default.svc"
	subject.CommonName = commonName
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(2022),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// 生成服务端的私钥
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Panic(err)
	}

	// 对服务端私钥签名
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		log.Panic(err)
	}
	serverCertPEM := new(bytes.Buffer)
	if err := pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	}); err != nil {
		log.Panic(err)
	}

	serverPrivKeyPem := new(bytes.Buffer)
	if err := pem.Encode(serverPrivKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	}); err != nil {
		log.Panic(err)
	}

	// 已经生成了ca server.pem server-key.pem
	if err := os.MkdirAll("/etc/webhook/certs/", 0666); err != nil {
		log.Panic(err)
	}

	if err := pkg.WriteFile("/etc/webhook/certs/tls.crt", serverCertPEM.Bytes()); err != nil {
		log.Panic(err)
	}

	if err := pkg.WriteFile("/etc/webhook/certs/tls.key", serverPrivKeyPem.Bytes()); err != nil {
		log.Panic(err)
	}

	log.Println("webhook server tls generated successfully")
	if err := CreateAdminssionConfig(caPEM); err != nil {
		log.Panic(err)
	}

	log.Println("Webhook admission configration object generated successfully")
}

func CreateAdminssionConfig(caCert *bytes.Buffer) error {
	clientset, err := pkg.InitkubernetesCli()
	if err != nil {
		return err
	}
	var (
		webhookNamespace, _   = os.LookupEnv("WEBHOOK_NAMESPACE")
		validateConfigName, _ = os.LookupEnv("VALIDATE_CONFIG")
		mutateConfigName, _   = os.LookupEnv("MUTATE_CONFIG")
		webhookService, _     = os.LookupEnv("WEBHOOK_SERVICE")
		validatePath, _       = os.LookupEnv("VALIDATE_PATH")
		mutatePath, _         = os.LookupEnv("MUTATE_PATH")
	)

	ctx := context.Background()
	if validateConfigName != "" {
		validateConfig := &admv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: validateConfigName,
			},
			Webhooks: []admv1.ValidatingWebhook{
				{
					Name: "io.ydzs.admission-validat",
					ClientConfig: admv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admv1.ServiceReference{
							Name:      webhookService,
							Namespace: webhookNamespace,
							Path:      &validatePath,
						},
					},
					Rules: []admv1.RuleWithOperations{
						{
							Operations: []admv1.OperationType{admv1.Create},
							Rule: admv1.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"pods"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admv1.SideEffectClass {
						se := admv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		validateAdmissionClient := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
		if _, err := validateAdmissionClient.Get(ctx, validateConfigName, metav1.GetOptions{}); err != nil {
			// 没有就创建
			if errors.IsNotFound(err) {
				if _, err := validateAdmissionClient.Create(ctx, validateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := validateAdmissionClient.Update(ctx, validateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	if mutateConfigName != "" {
		mutateConfig := &admv1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: mutateConfigName,
			},
			Webhooks: []admv1.MutatingWebhook{
				{
					Name: "io.ydzs.admission-mutate",
					ClientConfig: admv1.WebhookClientConfig{
						CABundle: caCert.Bytes(),
						Service: &admv1.ServiceReference{
							Name:      webhookService,
							Namespace: webhookNamespace,
							Path:      &mutatePath,
						},
					},
					Rules: []admv1.RuleWithOperations{
						{
							Operations: []admv1.OperationType{admv1.Create},
							Rule: admv1.Rule{
								APIGroups:   []string{"apps", ""},
								APIVersions: []string{"v1"},
								Resources:   []string{"deployments", "services"},
							},
						},
					},
					AdmissionReviewVersions: []string{"v1"},
					SideEffects: func() *admv1.SideEffectClass {
						se := admv1.SideEffectClassNone
						return &se
					}(),
				},
			},
		}
		mutateAdmissionClient := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations()
		if _, err := mutateAdmissionClient.Get(ctx, mutateConfigName, metav1.GetOptions{}); err != nil {
			// 没有就创建
			if errors.IsNotFound(err) {
				if _, err := mutateAdmissionClient.Create(ctx, mutateConfig, metav1.CreateOptions{}); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			if _, err := mutateAdmissionClient.Update(ctx, mutateConfig, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	return nil
}
