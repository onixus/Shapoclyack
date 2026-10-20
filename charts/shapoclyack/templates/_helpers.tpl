{{/*
Image reference: repository:tag, with @digest when one is pinned. The default
values pin every image by digest, like the kustomize base does.
*/}}
{{- define "shapoclyack.image" -}}
{{- if .digest -}}
{{ .repository }}:{{ .tag }}@{{ .digest }}
{{- else -}}
{{ .repository }}:{{ .tag }}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret a workload reads. existingSecrets.<key> wins; otherwise the
name the kustomize base uses, which the chart itself creates (dev placeholders)
or ExternalSecrets Operator materialises.
Args: dict "root" $ "key" <existingSecrets key> "default" <base name>
*/}}
{{- define "shapoclyack.secretName" -}}
{{- $override := index .root.Values.existingSecrets .key -}}
{{- if $override -}}{{ $override }}{{- else -}}{{ .default }}{{- end -}}
{{- end -}}

{{/*
Non-empty when the chart should render the dev-placeholder Secret for <key>:
neither an existing Secret nor ExternalSecrets supplies it.
Args: dict "root" $ "key" <existingSecrets key>
*/}}
{{- define "shapoclyack.generateSecret" -}}
{{- $override := index .root.Values.existingSecrets .key -}}
{{- if not (or $override .root.Values.externalSecrets.enabled) -}}true{{- end -}}
{{- end -}}
