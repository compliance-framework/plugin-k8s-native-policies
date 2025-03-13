package compliance_framework.template.k8s_deny_bad_image_registry

violation[{
    "title": "Container image is from an unapproved registry",
    "description": sprintf("Pod '%s' is using an unapproved image: %s", [pod.Name, pod.Image]),
    "severity": "high"
}] if {
    pod = input.Pods[_]
    not startswith(pod.Image, "ghcr.io/compliance-framework/")
}
