#!/bin/bash

# --- Configuración ---
# Nombre base para el directorio y archivos de salida
OUTPUT_BASENAME="k8s_inventory_$(date +%Y%m%d_%H%M%S)"
# Directorio de salida
OUTPUT_DIR="./${OUTPUT_BASENAME}"
# Extensión de archivo CSV
CSV_EXT=".csv"
# Namespaces a excluir de la recopilación detallada (cuando se usa -A)
EXCLUDED_NAMESPACES_LIST=("kube-system" "kube-public" "kube-node-lease") # Array de namespaces

# --- Crear directorio de salida ---
mkdir -p "$OUTPUT_DIR"
echo "Creando inventario en el directorio: $OUTPUT_DIR"
echo "Excluyendo namespaces: ${EXCLUDED_NAMESPACES_LIST[*]}"

# --- Cabeceras CSV ---
HEADERS_DEPLOYMENTS="Namespace,Name,ReplicasDesired,ReplicasAvailable,Strategy,Containers,Images,RequestsCPU,RequestsMemory,LimitsCPU,LimitsMemory,SelectorLabels"
HEADERS_STATEFULSETS="Namespace,Name,ReplicasDesired,ReplicasReady,Strategy,ServiceName,VolumeClaimTemplates,Containers,Images,RequestsCPU,RequestsMemory,LimitsCPU,LimitsMemory,SelectorLabels"
HEADERS_DAEMONSETS="Namespace,Name,DesiredScheduled,CurrentScheduled,ReadyScheduled,UpdateStrategy,Containers,Images,RequestsCPU,RequestsMemory,LimitsCPU,LimitsMemory,SelectorLabels"
HEADERS_SERVICES="Namespace,Name,Type,ClusterIP,ExternalIP,Ports,SelectorLabels"
HEADERS_INGRESSES="Namespace,Name,Class,Hosts,Paths,TLS_Secrets"
HEADERS_PVCS="Namespace,Name,Status,VolumeName,StorageClass,AccessModes,RequestedCapacity"
HEADERS_PVS="Name,Capacity,AccessModes,ReclaimPolicy,Status,ClaimNamespace,ClaimName,StorageClass,VolumeSourceType,VolumeSourceDetails"
HEADERS_STORAGECLASSES="Name,Provisioner,ReclaimPolicy,VolumeBindingMode,AllowVolumeExpansion,Parameters"
HEADERS_HPAS="Namespace,Name,ScaleTargetKind,ScaleTargetName,MinReplicas,MaxReplicas,CurrentReplicas,TargetMetricType,TargetMetricValue"
HEADERS_CONFIGMAPS="Namespace,Name"
HEADERS_SECRETS="Namespace,Name"
HEADERS_SERVICEACCOUNTS="Namespace,Name"
HEADERS_ROLES="Namespace,Name"
HEADERS_ROLEBINDINGS="Namespace,Name,RoleKind,RoleName,Subjects"
HEADERS_CLUSTERROLES="Name"
HEADERS_CLUSTERROLEBINDINGS="Name,RoleKind,RoleName,Subjects"
HEADERS_CRONJOBS="Namespace,Name,Schedule,Suspend,ActiveJobs,LastScheduleTime"
HEADERS_JOBS="Namespace,Name,Completions,Duration,Status"
HEADERS_NAMESPACES="Name,Status,Age"


# --- Funciones Auxiliares ---

# Función para inicializar archivo CSV con cabecera
init_csv() {
    local filepath="$1"
    local headers="$2"
    echo "$headers" > "$filepath"
    echo "Creado archivo: $filepath"
}

# Construye el field-selector para excluir namespaces
build_excluded_ns_selector() {
    local selector=""
    for ns_to_exclude in "${EXCLUDED_NAMESPACES_LIST[@]}"; do
        if [ -n "$selector" ]; then
            selector+=","
        fi
        selector+="metadata.namespace!=$ns_to_exclude"
    done
    echo "$selector"
}

# Función para extraer recursos y añadirlos al CSV correspondiente
# Uso: extract_to_csv <ResourceKind> <CSVFilePath> <Headers> <jqFilter> [-A | -n namespace | ""]
extract_to_csv() {
    local resource_kind=$1
    local csv_filepath=$2
    local headers=$3
    local jq_filter=$4
    local scope_arg=$5 # Puede ser -A, -n namespace, o "" para cluster-scoped

    echo "Procesando: $resource_kind"
    init_csv "$csv_filepath" "$headers"

    local k_cmd_array=("kubectl" "get" "$resource_kind")

    if [[ "$scope_arg" == "-A" ]]; then
        k_cmd_array+=("-A")
        local excluded_selector
        excluded_selector=$(build_excluded_ns_selector)
        if [ -n "$excluded_selector" ]; then
            k_cmd_array+=("--field-selector" "$excluded_selector")
        fi
    elif [[ -n "$scope_arg" && "$scope_arg" != "" ]]; then # Para un namespace específico (ej: -n my-ns)
        # Asegura que el argumento se divida correctamente (ej. "-n", "mynamespace")
        read -r -a scope_parts <<< "$scope_arg"
        k_cmd_array+=("${scope_parts[@]}")
    fi
    # Si scope_arg es "", no se añaden flags de namespace (para cluster-scoped)

    k_cmd_array+=("-o" "json")

    # echo "Ejecutando: ${k_cmd_array[*]}" # Descomentar para depurar
    if ! output=$("${k_cmd_array[@]}"); then
         echo "Advertencia: Falló el comando kubectl para $resource_kind. ${output}"
         # Continuar aunque falle kubectl para este recurso
         echo "Completado (con error): $resource_kind"
         return # Salir de la función para este recurso
    fi

    if ! echo "$output" | jq -r "$jq_filter" | sed 's/"//g' >> "$csv_filepath"; then
         echo "Advertencia: Falló jq o sed al procesar $resource_kind. El archivo CSV puede estar incompleto."
         # Continuar aunque falle jq/sed
    fi


    # Eliminar última línea si está vacía (puede ocurrir si jq no produce salida)
    [[ $(tail -n 1 "$csv_filepath" 2>/dev/null) == "" ]] && sed -i '$ d' "$csv_filepath" 2>/dev/null
    echo "Completado: $resource_kind"
}

# Función específica para recursos que sólo necesitan listar nombres (ConfigMaps, Secrets)
extract_names_only() {
    local resource_kind=$1
    local csv_filepath=$2
    local headers=$3

    echo "Procesando (solo nombres): $resource_kind"
    init_csv "$csv_filepath" "$headers"

    local k_cmd_array=("kubectl" "get" "$resource_kind")
    k_cmd_array+=("-A") # Siempre queremos todos los namespaces para esta función base

    local excluded_selector
    excluded_selector=$(build_excluded_ns_selector)
    if [ -n "$excluded_selector" ]; then
        k_cmd_array+=("--field-selector" "$excluded_selector")
    fi

    k_cmd_array+=("-o" "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name" "--no-headers")

    # echo "Ejecutando: ${k_cmd_array[*]}" # Descomentar para depurar
    if ! "${k_cmd_array[@]}" | awk '{print $1","$2}' >> "$csv_filepath"; then
      echo "Advertencia: No se pudieron obtener nombres para $resource_kind. El archivo CSV podría estar vacío."
    fi

    [[ $(tail -n 1 "$csv_filepath" 2>/dev/null) == "" ]] && sed -i '$ d' "$csv_filepath" 2>/dev/null
    echo "Completado (solo nombres): $resource_kind"
}


# --- Extracción de Datos ---

echo "Iniciando extracción de datos de Kubernetes..."

# 1. Namespaces (Cluster Scope, pero lo listamos primero)
NAMESPACE_CSV="${OUTPUT_DIR}/namespaces${CSV_EXT}"
extract_to_csv "namespaces" "$NAMESPACE_CSV" "$HEADERS_NAMESPACES" '.items[] | [.metadata.name, .status.phase, (.metadata.creationTimestamp | sub("\\.[0-9]+Z$";"Z"))] | @csv' "" # Scope "" para cluster, sin filtro NS aquí


# 2. Workloads (Deployments, StatefulSets, DaemonSets) - Iterando por contenedores
DEPLOYMENT_CSV="${OUTPUT_DIR}/deployments${CSV_EXT}"
JQ_DEPLOYMENTS='.items[] | . as $dep | .spec.template.spec.containers[] | [
    $dep.metadata.namespace,
    $dep.metadata.name,
    ($dep.spec.replicas // "N/A"),
    ($dep.status.availableReplicas // "N/A"),
    ($dep.spec.strategy.type // "RollingUpdate"),
    .name,
    .image,
    (.resources.requests.cpu // "N/A"),
    (.resources.requests.memory // "N/A"),
    (.resources.limits.cpu // "N/A"),
    (.resources.limits.memory // "N/A"),
    ($dep.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(";") // "N/A")
] | @csv'
extract_to_csv "deployments" "$DEPLOYMENT_CSV" "$HEADERS_DEPLOYMENTS" "$JQ_DEPLOYMENTS" "-A"

STATEFULSET_CSV="${OUTPUT_DIR}/statefulsets${CSV_EXT}"
JQ_STATEFULSETS='.items[] | . as $sts | .spec.template.spec.containers[] | [
    $sts.metadata.namespace,
    $sts.metadata.name,
    ($sts.spec.replicas // "N/A"),
    ($sts.status.readyReplicas // "N/A"),
    ($sts.spec.updateStrategy.type // "RollingUpdate"),
    ($sts.spec.serviceName // "N/A"),
    ($sts.spec.volumeClaimTemplates | map(.metadata.name) | join(";") // "N/A"),
    .name,
    .image,
    (.resources.requests.cpu // "N/A"),
    (.resources.requests.memory // "N/A"),
    (.resources.limits.cpu // "N/A"),
    (.resources.limits.memory // "N/A"),
    ($sts.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(";") // "N/A")
] | @csv'
extract_to_csv "statefulsets" "$STATEFULSET_CSV" "$HEADERS_STATEFULSETS" "$JQ_STATEFULSETS" "-A"

DAEMONSET_CSV="${OUTPUT_DIR}/daemonsets${CSV_EXT}"
JQ_DAEMONSETS='.items[] | . as $ds | .spec.template.spec.containers[] | [
    $ds.metadata.namespace,
    $ds.metadata.name,
    ($ds.status.desiredNumberScheduled // "N/A"),
    ($ds.status.currentNumberScheduled // "N/A"),
    ($ds.status.numberReady // "N/A"),
    ($ds.spec.updateStrategy.type // "RollingUpdate"),
    .name,
    .image,
    (.resources.requests.cpu // "N/A"),
    (.resources.requests.memory // "N/A"),
    (.resources.limits.cpu // "N/A"),
    (.resources.limits.memory // "N/A"),
    ($ds.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(";") // "N/A")
] | @csv'
extract_to_csv "daemonsets" "$DAEMONSET_CSV" "$HEADERS_DAEMONSETS" "$JQ_DAEMONSETS" "-A"


# 3. Networking (Services, Ingresses)
SERVICE_CSV="${OUTPUT_DIR}/services${CSV_EXT}"
JQ_SERVICES='.items[] | [
    .metadata.namespace,
    .metadata.name,
    .spec.type,
    (.spec.clusterIP // "N/A"),
    (if .spec.type == "LoadBalancer" then (.status.loadBalancer.ingress | map(.ip // .hostname) | join(";")) else (if .spec.externalIPs then (.spec.externalIPs | join(";")) else "N/A" end) end), # Añadido soporte para externalIPs
    (.spec.ports | map("\(.name // ""):\(.port):\(.targetPort):\(.protocol):\(.nodePort // "")") | join(";") // "N/A"),
    (.spec.selector | to_entries | map("\(.key)=\(.value)") | join(";") // "N/A")
] | @csv'
extract_to_csv "services" "$SERVICE_CSV" "$HEADERS_SERVICES" "$JQ_SERVICES" "-A"

INGRESS_CSV="${OUTPUT_DIR}/ingresses${CSV_EXT}"
JQ_INGRESSES='.items[] | [
    .metadata.namespace,
    .metadata.name,
    (.spec.ingressClassName // (.metadata.annotations."kubernetes.io/ingress.class" // "N/A")),
    (.spec.rules | map(.host // "*") | join(";") // "N/A"),
    (.spec.rules | map(.http.paths | map("\(.path // "/")(\(.pathType // "Prefix")) -> \(.backend.service.name):\(.backend.service.port.name // (.backend.service.port.number | tostring))") | join(",")) | join(";") // "N/A"), # Añadido pathType
    (.spec.tls | map(.secretName // "(default cert)") | join(";") // "N/A")
] | @csv'
extract_to_csv "ingresses.networking.k8s.io" "$INGRESS_CSV" "$HEADERS_INGRESSES" "$JQ_INGRESSES" "-A" # Usar nombre completo api


# 4. Storage (PVCs, PVs, StorageClasses)
PVC_CSV="${OUTPUT_DIR}/persistentvolumeclaims${CSV_EXT}"
JQ_PVCS='.items[] | [
    .metadata.namespace,
    .metadata.name,
    .status.phase,
    (.spec.volumeName // "N/A"),
    (.spec.storageClassName // "default"), # Default si no especificado
    (.spec.accessModes | join(";") // "N/A"),
    (.spec.resources.requests.storage // (.status.capacity.storage // "N/A")) # Usa status.capacity si spec.resources no está
] | @csv'
extract_to_csv "persistentvolumeclaims" "$PVC_CSV" "$HEADERS_PVCS" "$JQ_PVCS" "-A"

PV_CSV="${OUTPUT_DIR}/persistentvolumes${CSV_EXT}"
JQ_PVS='.items[] | [
    .metadata.name,
    (.spec.capacity.storage // "N/A"),
    (.spec.accessModes | join(";") // "N/A"),
    .spec.persistentVolumeReclaimPolicy,
    .status.phase,
    (.spec.claimRef.namespace // "N/A"),
    (.spec.claimRef.name // "N/A"),
    (.spec.storageClassName // "default"),
    (if .spec.gcePersistentDisk then "GCE PD" elif .spec.awsElasticBlockStore then "AWS EBS" elif .spec.azureDisk then "AzureDisk" elif .spec.azureFile then "AzureFile" elif .spec.csi then "CSI (" + (.spec.csi.driver // "?") + ")" elif .spec.nfs then "NFS" elif .spec.hostPath then "HostPath" else "Other/Unknown" end), # Mejorado CSI
    (if .spec.gcePersistentDisk then .spec.gcePersistentDisk.pdName elif .spec.awsElasticBlockStore then .spec.awsElasticBlockStore.volumeID elif .spec.azureDisk then .spec.azureDisk.diskName elif .spec.azureFile then .spec.azureFile.shareName elif .spec.csi then .spec.csi.volumeHandle else "N/A" end)
] | @csv'
extract_to_csv "persistentvolumes" "$PV_CSV" "$HEADERS_PVS" "$JQ_PVS" "" # Cluster-scoped

STORAGECLASS_CSV="${OUTPUT_DIR}/storageclasses${CSV_EXT}"
JQ_STORAGECLASSES='.items[] | [
    .metadata.name,
    .provisioner,
    (.reclaimPolicy // "Delete"),
    (.volumeBindingMode // "Immediate"),
    (.allowVolumeExpansion // "false"),
    (.parameters | to_entries | map("\(.key)=\(.value)") | join(";") // "N/A")
] | @csv'
extract_to_csv "storageclasses.storage.k8s.io" "$STORAGECLASS_CSV" "$HEADERS_STORAGECLASSES" "$JQ_STORAGECLASSES" "" # Usar nombre completo api


# 5. Autoscaling (HPAs)
HPA_CSV="${OUTPUT_DIR}/horizontalpodautoscalers${CSV_EXT}"
JQ_HPAS='.items[] | [
    .metadata.namespace,
    .metadata.name,
    .spec.scaleTargetRef.kind,
    .spec.scaleTargetRef.name,
    (.spec.minReplicas // "N/A"),
    .spec.maxReplicas,
    (.status.currentReplicas // "N/A"),
    (.spec.metrics | map(.type + ":" + (if .type == "Resource" then .resource.name else (.pods // .external // .object).metric.name end) ) | join(";") // "N/A"),
    (.spec.metrics | map(.type + ":" + (if .type == "Resource" then ((.resource.target.averageUtilization | tostring // "N/A") + "%" // (.resource.target.averageValue // "N/A")) else ((.pods // .external // .object).target.averageValue // (.pods // .external // .object).target.value // "N/A") end) ) | join(";") // "N/A")
] | @csv'
extract_to_csv "horizontalpodautoscalers.autoscaling" "$HPA_CSV" "$HEADERS_HPAS" "$JQ_HPAS" "-A" # Usar nombre completo api


# 6. Configuration (ConfigMaps, Secrets - Names Only)
CONFIGMAP_CSV="${OUTPUT_DIR}/configmaps${CSV_EXT}"
extract_names_only "configmaps" "$CONFIGMAP_CSV" "$HEADERS_CONFIGMAPS"

SECRET_CSV="${OUTPUT_DIR}/secrets${CSV_EXT}"
# Filtrar secretos de tipo service-account-token que son autogenerados
init_csv "$SECRET_CSV" "$HEADERS_SECRETS"
k_cmd_array_secrets=("kubectl" "get" "secrets" "-A")
excluded_selector_secrets=$(build_excluded_ns_selector)
if [ -n "$excluded_selector_secrets" ]; then
    k_cmd_array_secrets+=("--field-selector" "$excluded_selector_secrets,type!=kubernetes.io/service-account-token")
else
     k_cmd_array_secrets+=("--field-selector" "type!=kubernetes.io/service-account-token")
fi
k_cmd_array_secrets+=("-o" "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name" "--no-headers")
if ! "${k_cmd_array_secrets[@]}" | awk '{print $1","$2}' >> "$SECRET_CSV"; then
    echo "Advertencia: No se pudieron obtener nombres para secrets. El archivo CSV podría estar vacío."
fi
[[ $(tail -n 1 "$SECRET_CSV" 2>/dev/null) == "" ]] && sed -i '$ d' "$SECRET_CSV" 2>/dev/null
echo "Completado (solo nombres): secrets (excluyendo service-account-token)"


# 7. RBAC & Service Accounts (Basic Info)
SERVICEACCOUNT_CSV="${OUTPUT_DIR}/serviceaccounts${CSV_EXT}"
extract_names_only "serviceaccounts" "$SERVICEACCOUNT_CSV" "$HEADERS_SERVICEACCOUNTS"

ROLE_CSV="${OUTPUT_DIR}/roles${CSV_EXT}"
init_csv "$ROLE_CSV" "$HEADERS_ROLES"
k_cmd_array_roles=("kubectl" "get" "roles.rbac.authorization.k8s.io" "-A") # Usar nombre completo api
excluded_selector_roles=$(build_excluded_ns_selector)
if [ -n "$excluded_selector_roles" ]; then
    k_cmd_array_roles+=("--field-selector" "$excluded_selector_roles")
fi
k_cmd_array_roles+=("-o" "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name" "--no-headers")
if ! "${k_cmd_array_roles[@]}" | awk '{print $1","$2}' >> "$ROLE_CSV"; then
   echo "Advertencia: No se pudieron obtener nombres para roles. El archivo CSV podría estar vacío."
fi
[[ $(tail -n 1 "$ROLE_CSV" 2>/dev/null) == "" ]] && sed -i '$ d' "$ROLE_CSV" 2>/dev/null


ROLEBINDING_CSV="${OUTPUT_DIR}/rolebindings${CSV_EXT}"
JQ_ROLEBINDINGS='.items[] | [
    .metadata.namespace,
    .metadata.name,
    .roleRef.kind,
    .roleRef.name,
    (.subjects | map(.kind + ":" + .name + (if .namespace then "("+ .namespace +")" else "" end)) | join(";") // "N/A")
] | @csv'
extract_to_csv "rolebindings.rbac.authorization.k8s.io" "$ROLEBINDING_CSV" "$HEADERS_ROLEBINDINGS" "$JQ_ROLEBINDINGS" "-A" # Usar nombre completo api

CLUSTERROLE_CSV="${OUTPUT_DIR}/clusterroles${CSV_EXT}"
init_csv "$CLUSTERROLE_CSV" "$HEADERS_CLUSTERROLES"
if ! kubectl get clusterroles.rbac.authorization.k8s.io -o custom-columns=NAME:.metadata.name --no-headers >> "$CLUSTERROLE_CSV"; then # Usar nombre completo api
   echo "Advertencia: No se pudieron obtener nombres para clusterroles. El archivo CSV podría estar vacío."
fi
[[ $(tail -n 1 "$CLUSTERROLE_CSV" 2>/dev/null) == "" ]] && sed -i '$ d' "$CLUSTERROLE_CSV" 2>/dev/null

CLUSTERROLEBINDING_CSV="${OUTPUT_DIR}/clusterrolebindings${CSV_EXT}"
JQ_CLUSTERROLEBINDINGS='.items[] | [
    .metadata.name,
    .roleRef.kind,
    .roleRef.name,
    (.subjects | map(.kind + ":" + .name + (if .namespace then "("+ .namespace +")" else "" end)) | join(";") // "N/A")
] | @csv'
extract_to_csv "clusterrolebindings.rbac.authorization.k8s.io" "$CLUSTERROLEBINDING_CSV" "$HEADERS_CLUSTERROLEBINDINGS" "$JQ_CLUSTERROLEBINDINGS" "" # Usar nombre completo api


# 8. Jobs & CronJobs
CRONJOB_CSV="${OUTPUT_DIR}/cronjobs${CSV_EXT}"
JQ_CRONJOBS='.items[] | [
    .metadata.namespace,
    .metadata.name,
    .spec.schedule,
    (.spec.suspend // "false"),
    (.status.active | length // 0),
    ((.status.lastScheduleTime // "N/A") | if . != "N/A" then sub("\\.[0-9]+Z$";"Z") else . end)
] | @csv'
extract_to_csv "cronjobs.batch" "$CRONJOB_CSV" "$HEADERS_CRONJOBS" "$JQ_CRONJOBS" "-A" # Usar nombre completo api

JOB_CSV="${OUTPUT_DIR}/jobs${CSV_EXT}"
JQ_JOBS='.items[] | [
    .metadata.namespace,
    .metadata.name,
    (.spec.completions // "N/A"),
     (if .status.startTime and .status.completionTime then ((.status.completionTime | fromdateiso8601) - (.status.startTime | fromdateiso8601) | tostring) + "s" else "N/A" end),
    (if .status.succeeded and .status.succeeded > 0 then "Succeeded" elif .status.failed and .status.failed > 0 then "Failed" elif .status.active and .status.active > 0 then "Active" else "Unknown/Pending" end) # Mejorado status
] | @csv'
extract_to_csv "jobs.batch" "$JOB_CSV" "$HEADERS_JOBS" "$JQ_JOBS" "-A" # Usar nombre completo api


# --- Finalización ---
echo "------------------------------------------"
echo "Inventario de Kubernetes completado."
echo "Archivos CSV generados en: $OUTPUT_DIR"
echo "Se excluyeron los namespaces: ${EXCLUDED_NAMESPACES_LIST[*]} de la recolección detallada de recursos."

# Crear un tarball del directorio
TARBALL_NAME="${OUTPUT_BASENAME}.tar.gz"
echo "Creando archivo tar.gz: ${TARBALL_NAME}..."
# Usar -C para cambiar al directorio padre antes de archivar, evita incluir ./ en la ruta
# Usar basename para obtener solo el nombre del directorio a archivar
if tar -czf "${TARBALL_NAME}" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"; then
    echo "Archivo tarball creado exitosamente: ${TARBALL_NAME}"
else
    echo "Error: No se pudo crear el archivo tarball ${TARBALL_NAME}."
fi

exit 0

