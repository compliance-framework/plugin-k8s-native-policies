package compliance_framework.template.k8s_RBAC_must_be_enabled

test_violation_for_no_RBAC if {
    violation[_] with input as {
        "RBACEnabled" : false
    }
}
