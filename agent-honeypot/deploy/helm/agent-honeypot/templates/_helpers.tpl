{{- define "ahp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else if contains "agent-honeypot" .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-agent-honeypot" .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Prefix for cluster-scoped PersistentVolumes (unique per release namespace). */}}
{{- define "ahp.pvPrefix" -}}
{{- printf "%s-%s" (include "ahp.fullname" .) .Release.Namespace | trunc 60 | trimSuffix "-" -}}
{{- end -}}

{{- define "ahp.labels" -}}
app.kubernetes.io/name: agent-honeypot
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 }}
{{- end -}}

{{- define "ahp.selector" -}}
app.kubernetes.io/name: agent-honeypot
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ahp.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{- define "ahp.decoyBaseUrl" -}}
{{- if .Values.decoy.baseUrl -}}
{{- .Values.decoy.baseUrl -}}
{{- else if eq (int .Values.decoy.servicePort) 80 -}}
{{- printf "http://%s" (first .Values.decoy.hostnames) -}}
{{- else -}}
{{- printf "http://%s:%d" (first .Values.decoy.hostnames) (int .Values.decoy.servicePort) -}}
{{- end -}}
{{- end -}}

{{- define "ahp.validate" -}}
{{- if contains "OWNER" .Values.image.repository -}}
{{- fail "set image.repository to your published agent-honeypot image" -}}
{{- end -}}
{{- if not .Values.agents -}}
{{- fail "agents must list at least one agent" -}}
{{- end -}}
{{- range .Values.agents -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$" (toString .id)) -}}
{{- fail (printf "agent id %q must be a DNS label (lowercase letters, digits, '-')" (toString .id)) -}}
{{- end -}}
{{- end -}}
{{- if not .Values.decoy.hostnames -}}
{{- fail "decoy.hostnames must not be empty" -}}
{{- end -}}
{{- if eq .Values.storage.type "efs" -}}
{{- if not .Values.storage.efs.fileSystemId -}}
{{- fail "storage.efs.fileSystemId is required when storage.type=efs" -}}
{{- end -}}
{{- else if eq .Values.storage.type "pvc" -}}
{{- if ne .Values.agentNamespace .Release.Namespace -}}
{{- fail "storage.type=pvc requires agentNamespace to equal the release namespace (use storage.type=efs for cross-namespace isolation)" -}}
{{- end -}}
{{- else -}}
{{- fail "storage.type must be efs or pvc" -}}
{{- end -}}
{{- if not (has .Values.responder.mode (list "notify" "quarantine" "delete")) -}}
{{- fail "responder.mode must be notify, quarantine or delete" -}}
{{- end -}}
{{- end -}}

{{- define "ahp.restrictedContainer" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
capabilities:
  drop: ["ALL"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* Root, but only the file-ownership capabilities (allowed by Pod Security "baseline"). */}}
{{- define "ahp.rootPrepContainer" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: false
runAsUser: 0
runAsGroup: 0
capabilities:
  drop: ["ALL"]
  add: ["CHOWN", "DAC_OVERRIDE", "FOWNER"]
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "ahp.dataVolume" -}}
- name: data
  persistentVolumeClaim:
    claimName: {{ include "ahp.fullname" . }}-data
{{- end -}}

{{- define "ahp.prepareStateInit" -}}
- name: prepare-state
  image: {{ include "ahp.image" . }}
  imagePullPolicy: {{ .Values.image.pullPolicy }}
  command: ["sh", "-c", "mkdir -p /data/state && chown 10001:10001 /data/state && chmod 0700 /data/state"]
  securityContext:
    {{- include "ahp.rootPrepContainer" . | nindent 4 }}
  volumeMounts:
    - name: data
      mountPath: /data
{{- end -}}

{{- define "ahp.commonEnv" -}}
- name: AGENT_HONEYPOT_STATE
  value: /state
- name: AHP_ALERTS_JSON
  value: {{ toJson .Values.alerts | quote }}
- name: PYTHONDONTWRITEBYTECODE
  value: "1"
- name: PYTHONUNBUFFERED
  value: "1"
{{- end -}}

{{/* Planter pod spec. Call with (dict "root" $ "rotate" <bool>). */}}
{{- define "ahp.planterPodSpec" -}}
{{- $root := .root -}}
{{- $fn := include "ahp.fullname" $root -}}
{{- $specs := list -}}
{{- range $root.Values.agents -}}
{{- $specs = append $specs (printf "%s:%d:%d" (toString .id) (int (.uid | default 1000)) (int (.gid | default 1000))) -}}
{{- end -}}
serviceAccountName: {{ $fn }}-planter
automountServiceAccountToken: false
restartPolicy: Never
securityContext:
  seccompProfile:
    type: RuntimeDefault
{{- with $root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
containers:
  - name: planter
    image: {{ include "ahp.image" $root }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    command: ["sh", "/config/plant.sh"]
    env:
      - name: AGENTS
        value: {{ join " " $specs | quote }}
      - name: ROTATE
        value: {{ .rotate | toString | quote }}
      - name: AHP_ALERTS_JSON
        value: '[{"type":"console"}]'
      - name: PYTHONDONTWRITEBYTECODE
        value: "1"
    securityContext:
      {{- include "ahp.rootPrepContainer" $root | nindent 6 }}
    resources:
      {{- toYaml $root.Values.planter.resources | nindent 6 }}
    volumeMounts:
      - name: data
        mountPath: /data
      - name: config
        mountPath: /config
        readOnly: true
volumes:
  {{- include "ahp.dataVolume" $root | nindent 2 }}
  - name: config
    configMap:
      name: {{ $fn }}-config
{{- with $root.Values.planter.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
