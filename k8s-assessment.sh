# Kubernetes Assessment Script (`k8s-assessment.sh`)
**Provided by Axmos Technologies**

## Overview

This script performs a detailed assessment of a Kubernetes cluster by gathering configuration data for various key resources. Its primary purpose is to create an inventory that aids in tasks such as:

*   **Cloud Migration Planning**: Specifically useful when planning migrations (e.g., from Azure Kubernetes Service (AKS) to Google Kubernetes Engine (GKE)), helping to identify resources, dependencies, and configurations that need attention.
*   **Resource Analysis**: Understanding resource requests and limits across workloads.
*   **Configuration Auditing**: Getting a snapshot of deployed services, storage, networking rules, and RBAC configurations.
*   **General Cluster Inventory**: Creating a structured overview of the cluster's state.

The script extracts information using `kubectl` and `jq`, processing the data into multiple CSV (Comma-Separated Values) files, making it easy to analyze using spreadsheet software or other data analysis tools. It focuses on collecting metadata and configuration details relevant for assessment, **without** reading sensitive data like Secret values.

## Prerequisites

Before running this script, ensure you have the following:

1.  **`kubectl`**: Installed and configured with access to the target Kubernetes cluster you wish to assess. Verify connectivity with `kubectl cluster-info`.
2.  **`jq`**: The command-line JSON processor must be installed. You can typically install it using your system's package manager:
    *   Debian/Ubuntu: `sudo apt-get update && sudo apt-get install jq`
    *   CentOS/RHEL/Fedora: `sudo yum install jq` or `sudo dnf install jq`
    *   macOS (using Homebrew): `brew install jq`
3.  **Bash Shell**: A standard Bash-compatible shell environment (common in Linux and macOS).
4.  **Kubernetes Permissions**: The `kubectl` context used must have sufficient RBAC (Role-Based Access Control) permissions to `get` and `list` the targeted resources across relevant namespaces and cluster-scoped resources. For a comprehensive assessment, read-only permissions equivalent to `view` or potentially `cluster-admin` (if needing to list *all* resources without restriction) might be necessary. The script performs **read-only** operations.

## Usage Instructions

1.  **Save the Script**: Save the script content provided to a file named `k8s-assessment.sh`.
2.  **Make it Executable**: Open your terminal/command prompt, navigate to the directory where you saved the file, and grant execute permissions:
    ```bash
    chmod +x k8s-assessment.sh
    ```
3.  **Run the Script**: Execute the script from the same directory:
    ```bash
    ./k8s-assessment.sh
    ```
4.  **Execution Process**:
    *   The script will first create a timestamped directory (e.g., `k8s_inventory_20231027_103000/`) in the current working directory.
    *   It will then proceed to query the Kubernetes API for different resource types.
    *   Progress messages indicating which resource type is being processed will be printed to the console.
    *   For each resource type, a corresponding CSV file will be created inside the timestamped directory.
    *   Finally, the script will create a compressed tarball archive (`.tar.gz`) containing the entire output directory (e.g., `k8s_inventory_20231027_103000.tar.gz`) in the current working directory for easy sharing and storage.

## What Data is Collected?

The script queries the Kubernetes API to gather information about the following resource types:

*   **Namespaces**: List of all namespaces, their status, and age.
*   **Workloads**:
    *   `Deployments`: Replica counts, strategy, container images, resource requests/limits, selectors.
    *   `StatefulSets`: Replica counts, strategy, service name, volume claim templates, container images, resource requests/limits, selectors.
    *   `DaemonSets`: Scheduling status, update strategy, container images, resource requests/limits, selectors.
    *   `CronJobs`: Schedule, suspend status, active job count, last schedule time.
    *   `Jobs`: Completion count, status, duration.
*   **Networking**:
    *   `Services`: Type (ClusterIP, NodePort, LoadBalancer), ClusterIP, External/LoadBalancer IP(s), ports, selectors.
    *   `Ingresses` (networking.k8s.io/v1): Ingress class, host rules, backend paths, TLS configuration (secret names).
*   **Storage**:
    *   `PersistentVolumeClaims` (PVCs): Status, bound Volume name, storage class, access modes, requested capacity.
    *   `PersistentVolumes` (PVs): Capacity, access modes, reclaim policy, status, claim reference (namespace/name), storage class, volume source type (e.g., `AzureDisk`, `GCEPersistentDisk`, `CSI`, `NFS`).
    *   `StorageClasses`: Provisioner name, reclaim policy, volume binding mode, parameters.
*   **Configuration**:
    *   `ConfigMaps`: Namespace and name only. **Values are NOT read.**
    *   `Secrets`: Namespace and name only. **Values are NOT read.** Auto-generated `kubernetes.io/service-account-token` secrets are excluded.
*   **Autoscaling**:
    *   `HorizontalPodAutoscalers` (HPAs): Target workload (kind/name), min/max replica counts, current replica count, target metrics definition.
*   **RBAC & Service Accounts**:
    *   `ServiceAccounts`: Namespace and name only.
    *   `Roles`: Namespace and name only.
    *   `RoleBindings`: Namespace, name, role reference (Kind/Name), subjects (users, groups, service accounts).
    *   `ClusterRoles`: Name only.
    *   `ClusterRoleBindings`: Name, role reference (Kind/Name), subjects.

## Generated Output Files (CSVs)

The script generates the following CSV files within the timestamped output directory:

*   `namespaces.csv`
*   `deployments.csv`
*   `statefulsets.csv`
*   `daemonsets.csv`
*   `services.csv`
*   `ingresses.csv`
*   `persistentvolumeclaims.csv`
*   `persistentvolumes.csv`
*   `storageclasses.csv`
*   `horizontalpodautoscalers.csv`
*   `configmaps.csv`
*   `secrets.csv`
*   `serviceaccounts.csv`
*   `roles.csv`
*   `rolebindings.csv`
*   `clusterroles.csv`
*   `clusterrolebindings.csv`
*   `cronjobs.csv`
*   `jobs.csv`

Each CSV file contains columns corresponding to the key information gathered for that resource type, as listed in the section above.

**Additionally, a `.tar.gz` archive containing all these CSV files is created in the directory where the script was run.**

## Important: Excluded Namespaces

By default, the script **excludes** resources from the following namespaces during the detailed collection process to focus on user-deployed applications and avoid capturing internal/managed components:

*   `kube-system`
*   `kube-public`
*   `kube-node-lease`

This behavior is intentional. Components within these namespaces are typically managed by the Kubernetes platform provider (like AKS, EKS, GKE) and are not meant to be directly migrated or managed by users in the same way application workloads are. Capturing them would add significant noise irrelevant to most application migration assessments. The full list of all namespaces *is* captured in `namespaces.csv` for completeness.

The exclusion list (`EXCLUDED_NAMESPACES_LIST`) can be modified near the top of the `k8s-assessment.sh` script if necessary for specific use cases, but this is generally not recommended for standard assessments.

## Attribution

This Kubernetes assessment script is provided by **Axmos Technologies**.

## Support and Questions

For further assistance, questions regarding this script, understanding the output, or inquiries about application modernization strategies and cloud migration services, please do not hesitate to contact the **Axmos App Mod (Application Modernization) team**.

*   **Contact**: felipe@axmos.tech, cristobal@axmos.tech 

## Notes and Disclaimers

*   **Read-Only Operation**: The script uses `kubectl get` commands, which are read-only operations. It does not make any changes to your Kubernetes cluster configuration.
*   **Data Sensitivity**: While the script avoids reading sensitive data like secret values, the collected metadata (resource names, labels, image names, configurations) might still be considered sensitive within your organization's context. Please handle the generated CSV files and tarball securely and according to your company's policies.
*   **Performance Impact**: On very large clusters with thousands of resources, the script might take a considerable amount of time to complete and may consume noticeable CPU/memory on the machine where `kubectl` and `jq` are executed.
*   **Analysis Required**: The generated CSV files provide raw inventory data. This data serves as a foundation for further analysis, interpretation, and decision-making regarding migration efforts, resource optimization, or configuration reviews.

