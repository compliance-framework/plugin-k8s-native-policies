package compliance_framework.template.k8s_RBAC_must_be_enabled

violation[{
    "title": "RBAC is not enabled",
    "description": "RBAC is not enabled for cluster",
    "severity": "high"
}] if {
    not input.RBACEnabled
}
