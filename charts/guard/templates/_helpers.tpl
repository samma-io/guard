{{- define "guard.labels" -}}
app.kubernetes.io/name: guard
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: samma
{{- end }}

{{- define "guard.selector" -}}
app.kubernetes.io/name: guard
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
