package compliance_framework.template.k8s_deny_bad_image_registry

test_allowed_pods if {
    count(violation) == 0 with input as {
        "Pods": [
            {"Name": "nginx-deployment-1", "Image": "ghcr.io/compliance-framework/nginx:v1.0"},
            {"Name": "nginx-deployment-2", "Image": "ghcr.io/compliance-framework/app:v2.3"}
        ]
    }
}

test_violation_for_untrusted_pod if {
    count(violation) == 1 with input as {
        "Pods": [
            {"Name": "nginx-deployment-1", "Image": "ghcr.io/compliance-framework/nginx:v1.0"},
            {"Name": "bad-pod", "Image": "docker.io/library/nginx:latest"}
        ]
    }
}

test_multiple_violations if {
    count(violation) == 3 with input as {
        "Pods": [
            {"Name": "trusted-app", "Image": "ghcr.io/compliance-framework/app:v1.2.3"},
            {"Name": "bad-app-1", "Image": "docker.io/library/nginx:latest"},
            {"Name": "bad-app-2", "Image": "k8s.gcr.io/coredns/coredns:v1.8.6"},
            {"Name": "bad-app-3", "Image": "k8s.gcr.io/kube-apiserver:v1.24.3"}
        ]
    }
}
