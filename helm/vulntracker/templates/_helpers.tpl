{{- define "vulntracker.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "vulntracker.fullname" -}}
{{- .Release.Name -}}-{{- .Chart.Name -}}
{{- end -}}

{{- define "vulntracker.labels" -}}
app.kubernetes.io/name: {{ include "vulntracker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "vulntracker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vulntracker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vulntracker.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- .Values.serviceAccount.name | default (include "vulntracker.fullname" .) -}}
{{- else -}}
{{- .Values.serviceAccount.name | default "default" -}}
{{- end -}}
{{- end -}}
