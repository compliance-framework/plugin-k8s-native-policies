package compliance_framework.template.k8s_deny_bad_image_registry

test_violation_for_untrusted_image if {
    violation[_] with input as {"Image": "docker.io/library/nginx:latest"}
}