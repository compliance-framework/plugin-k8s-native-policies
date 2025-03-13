package compliance_framework.template.k8s_deny_bad_image_registry

violation[{
    "title": "Container image is from an unapproved registry",
    "description": sprintf("Container image '%s' does not match the allowed registry 'ghcr.io/compliance-framework/**/*'", [input.Image]),
    "severity": "high"
}] if {
    not startswith(input.Image, "ghcr.io/compliance-framework/")
}
