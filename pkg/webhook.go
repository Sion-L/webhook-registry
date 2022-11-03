package pkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	Admv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog"
	"net/http"
	"strings"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecFactory  = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecFactory.UniversalDeserializer()
)

const (
	AnnotationMutateKey = "io.ydzs.admission-validat/mutate"
	AnnotationStatusKey = "io.ydzs.admission-validat/status"
)

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type HookServer struct {
	Port     int
	CertFile string
	KeyFile  string
}

type WebHookServer struct {
	Server       *http.Server
	WhiteListPag []string // 白名单的镜像仓库列表
}

func (s *WebHookServer) ServHandler(writer http.ResponseWriter, request *http.Request) {
	var body []byte
	if request.Body != nil {
		if data, err := ioutil.ReadAll(request.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		klog.Error("empty data body")
		http.Error(writer, "empty data body", http.StatusBadRequest)
		return
	}

	// 校验 content-type
	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Errorf("Content-Type is %s, but expect application/json", contentType)
		http.Error(writer, "Content-Type invalid,expect application/json", http.StatusUnsupportedMediaType)
		return
	}

	// 数据序列化 - validate和mutate请求的数据都是 AdmissionReview
	var admissionResponse *Admv1.AdmissionResponse
	requestAdmissionReview := Admv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &requestAdmissionReview); err != nil {
		klog.Errorf("Can't decode body: %v", err)
		admissionResponse = &Admv1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		// 序列化成功,获取到了请求的admissionReview的数据,下面开始做业务的处理
		if request.URL.Path == "/mutate" {
			admissionResponse = s.mutate(&requestAdmissionReview)
		} else if request.URL.Path == "/validate" {
			admissionResponse = s.validate(&requestAdmissionReview)
		}
	}

	// 业务处理完成后，构造返回的 admissionReview 结构体
	responseAdmissionReview := Admv1.AdmissionReview{}
	// admission/v1
	responseAdmissionReview.APIVersion = requestAdmissionReview.APIVersion
	responseAdmissionReview.Kind = requestAdmissionReview.Kind
	if admissionResponse != nil {
		responseAdmissionReview.Response = admissionResponse
		if requestAdmissionReview.Request != nil {
			// 返回跟请求相同的uuid
			responseAdmissionReview.Response.UID = requestAdmissionReview.Request.UID
		}
	}
	klog.Info(fmt.Sprintf("sending response: %v", responseAdmissionReview.Response))
	// send response
	respBytes, err := json.Marshal(responseAdmissionReview)
	if err != nil {
		klog.Errorf("Can't encode response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't encode response: %v", err), http.StatusInternalServerError)
		return
	}
	// 序列化成功
	klog.Info("Ready to write response...")
	if _, err := writer.Write(respBytes); err != nil {
		klog.Errorf("Can't write response: %v", err)
		http.Error(writer, fmt.Sprintf("Can't write response: %v", err), http.StatusInternalServerError)
		return
	}

}

func (s *WebHookServer) validate(a *Admv1.AdmissionReview) *Admv1.AdmissionResponse {
	//TODO
	req := a.Request
	var (
		allowed = true
		code    = 200
		message = ""
	)
	//klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%v UID=%v Operation=%v UserInfo=%v", req.Kind.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)
	// 校验pod
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		klog.Errorf("Can't unmarshal object raw: %v", err)
		allowed = false
		code = http.StatusBadRequest
		return &Admv1.AdmissionResponse{
			Allowed: allowed,
			Result: &metav1.Status{
				Code:    int32(code),
				Message: err.Error(),
			},
		}
	}

	// 拿到请求包含中的pod对象，处理真正的业务逻辑
	for _, container := range pod.Spec.Containers {
		var whiteList = false
		for _, reg := range s.WhiteListPag {
			if strings.HasPrefix(container.Image, reg) {
				// 容器镜像命中了，在白名单里面
				whiteList = true
			}
		}
		// 容器镜像没命中
		if !whiteList {
			allowed = false
			code = http.StatusForbidden
			message = fmt.Sprintf("%s image comes from an untrusted validat! Only image from %v are allowed", container.Image, s.WhiteListPag)
			break
		}
	}

	return &Admv1.AdmissionResponse{
		Allowed: allowed,
		Result: &metav1.Status{
			Code:    int32(code),
			Message: message,
		},
	}
}

func (s *WebHookServer) mutate(a *Admv1.AdmissionReview) *Admv1.AdmissionResponse {
	// 创建deployment和service时，自动添加annotation
	req := a.Request

	var (
		objectMeta *metav1.ObjectMeta // anntation在这里面

	)

	klog.Infof("AdmissionReview for Kind=%s, Namespace=%s Name=%v UID=%v Operation=%v UserInfo=%v", req.Kind.Kind, req.Namespace, req.Name, req.UID, req.Operation, req.UserInfo)

	switch req.Kind.Kind {
	// 创建deployment
	case "Deployment":
		var deployment appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &deployment); err != nil {
			klog.Errorf("Can't not unmarshal raw object: %v", err)
			return &Admv1.AdmissionResponse{
				Result: &metav1.Status{
					Code:    http.StatusBadRequest,
					Message: err.Error(),
				},
			}
		}
		// 解析成功，获取annotation进行判断是否添加新的anntation
		objectMeta = &deployment.ObjectMeta
	// 创建service
	case "Service":
		var service corev1.Service
		if err := json.Unmarshal(req.Object.Raw, &service); err != nil {
			klog.Errorf("Can't not unmarshal raw object: %v", err)
			return &Admv1.AdmissionResponse{
				Result: &metav1.Status{
					Code:    http.StatusBadRequest,
					Message: err.Error(),
				},
			}
		}
		objectMeta = &service.ObjectMeta
	default:
		return &Admv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("Can't handler the kind(%s) object", req.Kind.Kind),
			},
		}
	}

	// 判断是否是要真的执行mutate操作
	if !mutationRequired(objectMeta) { // 不需要执行
		return &Admv1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := map[string]string{ // 需要执行
		AnnotationStatusKey: "mutated",
	}
	var patch []patchOperation
	patch = append(patch, mutateAnnotations(objectMeta.GetAnnotations(), annotations)...)

	// 将path组装到response中
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		klog.Errorf("patch marshal err:%v", err)
		return &Admv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		}
	}

	return &Admv1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *Admv1.PatchType {
			pt := Admv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func mutationRequired(meta *metav1.ObjectMeta) bool {
	annotation := meta.GetAnnotations()
	if annotation == nil {
		annotation = map[string]string{} // 没得到则做一个初始化
	}

	var required bool
	switch strings.ToLower(annotation[AnnotationMutateKey]) {
	default:
		required = true
	case "n", "no", "false", "off":
		required = false
	}
	status := annotation[AnnotationStatusKey]
	if strings.ToLower(status) == "mutated" {
		required = false
	}
	klog.Infof("Mutation policy for %s/%s: required: %v", meta.Name, meta.Namespace, required)
	return required
}

func mutateAnnotations(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" { // 如果应用中没有annotation
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else { // 应用中包含了annotation，做替换
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return
}
