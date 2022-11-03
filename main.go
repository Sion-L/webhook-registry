package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/Sion-L/admission-validat/pkg"
	"k8s.io/klog"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"syscall"
)

func main() {
	// http 支持tls
	var param pkg.HookServer
	// 命令行参数
	flag.IntVar(&param.Port, "port", 443, "WebHook Server Port")
	flag.StringVar(&param.CertFile, "CertFile", "/etc/webhook/certs/tls.crt", "x509 certification file")
	flag.StringVar(&param.KeyFile, "keyFile", "/etc/webhook/certs/tls.key", "x509 private key file")
	flag.Parse()

	certs, err := tls.LoadX509KeyPair(param.CertFile, param.KeyFile)
	if err != nil {
		klog.Errorf("failed to load key pair: %v", err)
		return
	}

	// 实例化一个webhookserver
	whsrv := pkg.WebHookServer{
		Server: &http.Server{
			Addr:      fmt.Sprintf(":%v", param.Port),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{certs}},
		},
		WhiteListPag: strings.Split(os.Getenv("WHITELIST_PAG"), ","),
	}

	// 定义http server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", whsrv.ServHandler)
	mux.HandleFunc("/mutate", whsrv.ServHandler)
	whsrv.Server.Handler = mux // 赋值定义的handler

	// 在一个新的goroutine去启动 webhookserver
	go func() {
		if err := whsrv.Server.ListenAndServeTLS("", ""); err != nil {
			klog.Errorf("Failed to listen and serve webhook server: %v", err)
		}
	}()

	klog.Info("Server started")

	// 监听os的关闭信号,应用杀掉会得到信号
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	klog.Infof("Got OS shutdown signal, shutting down webhook server gracefully...")
	if err := whsrv.Server.Shutdown(context.Background()); err != nil {
		klog.Errorf("HTTP server Shutdown: %v", err)
	}
}
