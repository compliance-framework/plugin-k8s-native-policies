package compliance_framework.template.k8s_pods_deny_pods_with_host_meta

violation[{
    "title": "Pod is using host network",
    "description": sprintf("Pod '%s' is using host network", [pod.Name]),
    "severity": "high"
}] if {
    pod = input.Pods[_]
    container = pod.Spec.Containers[_]
    port = container.Ports[_]
    
    port.HostPort != 0
}
