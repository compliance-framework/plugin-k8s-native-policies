package compliance_framework.template.k8s_pods_deny_elevated_privileges

test_no_privilege if {
    count(violation) == 0 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": false
                            }
                        }
                    ]
                }
            }
        ]
    }
}

test_privileged_pod if {
    count(violation) == 1 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": true
                            }
                        }
                    ]
                }
            }
        ]
    }
}

test_multiple_privileged_pods if {
    count(violation) == 2 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": true
                            }
                        }
                    ]
                }
            },
            {
                "Name": "nginx-pod-2",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": true
                            }
                        }
                    ]
                }
            }
        ]
    }
}

test_no_privilege_multiple_containers if {
    count(violation) == 0 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": false
                            }
                        },
                        {
                            "Name": "sidecar",
                            "SecurityContext": {
                                "Privileged": false
                            }
                        }
                    ]
                }
            }
        ]
    }
}

test_mixed_privilege if {
    count(violation) == 1 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "SecurityContext": {
                                "Privileged": true
                            }
                        },
                        {
                            "Name": "sidecar",
                            "SecurityContext": {
                                "Privileged": false
                            }
                        }
                    ]
                }
            }
        ]
    }
}
