{{- define "requestor.name" -}}
{{- printf "%s-kube-token-requestor" .Release.Name | trunc 53 | trimSuffix "-" -}}
{{- end -}}
{{- define "requestor.labels" -}}
app.kubernetes.io/name: kube-token-requestor
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}
{{- define "requestor.binding" -}}
subjects:
  - kind: ServiceAccount
    name: {{ include "requestor.name" . }}
    namespace: {{ .Release.Namespace }}
{{- end -}}
