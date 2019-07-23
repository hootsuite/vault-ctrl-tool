# Using Kubernetes

Vault Control Tool can easily be run as both an init container to populate various files, as well as a sidecar to
keep leases fresh while your service is running. You will need a Service Account, some mounts for the configuration
and leases, configuration for the init and sidecar containers and then the actual vault configuration. 

## Service Account

Pods authenticate themselves to Vault by using their ServiceAccount Token. So you'll need a ServiceAccount mounted
in your pod:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-example
  namespace: default
# If you have specific authentication required to access your Docker registry, you'll need to
# include the imagePullSecrets too.
imagePullSecrets:
  - name: docker-registry-auth
---
# Allow my-service to use the TokenReview API
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: my-example-tokenreview-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: my-example
  namespace: default
```

## Mounts

This tool needs to read its configuration from one mount, and requires a place to writeout its lease information. The
configuration is only needed for the init container.

```yaml
...
    spec:
      volumes:
        # This volume is shared between the vault-ctrl-tool and any container needing secrets
        - name: vault-secrets-volume
          emptyDir: {}
        # This volume is exclusive to the vault-ctrl-tool init and sidecar containers.
        - name: vault-leases-volume
          emptyDir: {}
        # This volume is exclusive to the vault-ctrl-tool init container.
        - name: vault-config-volume
          configMap:
            name: my-example-vault-configmap
   serviceAccount: my-example
```

## Init Container
```yaml
      initContainers:
      - name: vault-init
        image: docker-registry.hootsuite.com/tools/vault-ctrl-tool:latest
        resources:
          limits:
            cpu: 1
            memory: 200Mi
          requests:
            cpu: 0.1
            memory: 64Mi
        env:
        # You can set VAULT_ADDR in different ways, or possibly have it setup as an external service. -- YMMV
         - name: VAULT_ADDR
           valueFrom:
             configMapKeyRef:
               name: vault
               key: vault_address
               optional: false
        # This is the path inside Vault where authentication requests will be sent.
         - name: K8S_LOGIN_PATH
           valueFrom:
             configMapKeyRef:
               name: vault
               key: vault_k8s_path
               optional: false
        command:
          - "/vault-ctrl-tool"
          - "--init"
          - "--json-log"
          - "--k8s-auth-role"
          - "my-example"
          - "--input-prefix"
          - "/etc/vault-config"
          - "--output-prefix"
          - "/etc/secrets"
        volumeMounts:
        - name: vault-secrets-volume
          mountPath: "/etc/secrets"
        - name: vault-config-volume
          mountPath: "/etc/vault-config"
        - name: vault-leases-volume
          mountPath: "/tmp/vault-leases"

```

## Sidecar Container

```yaml
      - name: vault-sidecar
        image: docker-registry.hootsuite.com/tools/vault-ctrl-tool:latest
        resources:
          limits:
            cpu: 1
            memory: 200Mi
          requests:
            cpu: 0.1
            memory: 64Mi
        env:
        # You can set VAULT_ADDR in different ways, or possibly have it setup as an external service. -- YMMV
         - name: VAULT_ADDR
           valueFrom:
             configMapKeyRef:
               name: vault
               key: vault_address
               optional: false
        command:
          - "/vault-ctrl-tool"
          - "--sidecar"
          - "--json-log"
          - "--input-prefix"
          - "/etc/vault-config"
          - "--output-prefix"
          - "/etc/secrets"
        volumeMounts:
        - name: vault-secrets-volume
          mountPath: "/etc/secrets"
        - name: vault-config-volume
          mountPath: "/etc/vault-config"
        - name: vault-leases-volume
          mountPath: "/tmp/vault-leases"
```
