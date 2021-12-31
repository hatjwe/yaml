package moresec.kubernetes.CKV_K8S_1

import data.lib.kubernetes
import data.lib.utils
import future.keywords.in

__rego_metadata__ := {
	"id": "CKV_K8S_1",
	"title": "检查子项设置hostPID为true",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "不允许共享主机进程ID命名空间的容器",
	"recommended_actions": "检查子项设置hostPID为false",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID {
	kubernetes.host_pids[_] == true
}

deny[res] {
	failHostPID

	msg := kubernetes.format(sprintf("检查子项设置hostPID为false", []))
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
