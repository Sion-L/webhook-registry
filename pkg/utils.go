package pkg

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
)

func WriteFile(filePath string, sCert []byte) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}

	defer f.Close()
	if _, err := f.Write(sCert); err != nil {
		return err
	}

	return nil
}

func InitkubernetesCli() (*kubernetes.Clientset, error) {
	var (
		err    error
		config *rest.Config
	)

	if config, err = rest.InClusterConfig(); err != nil {
		return nil, err
	}

	// 创建clientset对象
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
