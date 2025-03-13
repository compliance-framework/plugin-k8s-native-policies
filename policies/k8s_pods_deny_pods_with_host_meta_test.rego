package compliance_framework.template.k8s_pods_deny_pods_with_host_meta

import data.compliance_framework.template.k8s_pods_deny_pods_with_host_meta

test_no_host_network if {
    count(violation) == 0 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "Ports": [
                                {
                                    "HostPort": 0
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
}

test_host_network_used if {
    count(violation) == 1 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "Ports": [
                                {
                                    "HostPort": 8080
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
}

test_multiple_violations if {
    count(violation) == 2 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "Ports": [
                                {
                                    "HostPort": 8080
                                }
                            ]
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
                            "Ports": [
                                {
                                    "HostPort": 9090
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
}

test_mixed_host_ports if {
    count(violation) == 1 with input as {
        "Pods": [
            {
                "Name": "nginx-pod-1",
                "Spec": {
                    "Containers": [
                        {
                            "Name": "nginx",
                            "Ports": [
                                {
                                    "HostPort": 0
                                },
                                {
                                    "HostPort": 8080
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
}
