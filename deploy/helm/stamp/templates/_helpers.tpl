{{/*
Names.
*/}}
{{- define "stamp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "stamp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "stamp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "stamp.labels" -}}
helm.sh/chart: {{ include "stamp.chart" . }}
app.kubernetes.io/name: {{ include "stamp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: stamp
stamp.dev/topology: {{ .Values.topology }}
{{- end -}}

{{- define "stamp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "stamp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "stamp.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/*
stamp.tiers is the whole difference between the two topologies, in one place.

It returns a list of tier dicts, each of which becomes one Deployment and one
Service. A tier carries the --roles value it runs, the surfaces it binds, the
database Secret it reads its DSN from, and whether it is the tier that migrates.

Which surfaces a role serves is not an operator choice — it is where the routes
are mounted in internal/api — so it is decided here rather than in values.yaml:

  check     PEP
  decide    console (approvals, inbox, audit views) and callback (MFA return,
            external challenge completion)
  consumer  callback (HTTP velocity ingest)
  api       console (policy, revision, governance)
  console   console (the bundle and its configuration document)
*/}}
{{- define "stamp.tiers" -}}
{{- $top := . -}}
{{- $callback := .Values.listeners.callback.enabled -}}
{{- $tiers := list -}}
{{- if eq .Values.topology "all-in-one" -}}
  {{- $surfaces := list "pep" "console" -}}
  {{- if $callback -}}{{- $surfaces = append $surfaces "callback" -}}{{- end -}}
  {{- $tiers = append $tiers (dict
      "name" "all"
      "roles" "all"
      "tier" .Values.allInOne
      "surfaces" $surfaces
      "credential" .Values.database.credentials.allInOne
      "migrate" .Values.database.migrate
      "applyGrants" .Values.database.applyGrants) -}}
{{- else if eq .Values.topology "split" -}}
  {{- range $role := list "check" "decide" "consumer" "api" "console" -}}
    {{- $spec := index $top.Values.roles $role -}}
    {{- if $spec.enabled -}}
      {{- $surfaces := list -}}
      {{- if eq $role "check" -}}
        {{- $surfaces = list "pep" -}}
      {{- else if eq $role "decide" -}}
        {{- $surfaces = list "console" -}}
        {{- if $callback -}}{{- $surfaces = append $surfaces "callback" -}}{{- end -}}
      {{- else if eq $role "consumer" -}}
        {{- if not $callback -}}
          {{- fail "topology=split with roles.consumer.enabled needs listeners.callback.enabled: the consumer role serves HTTP velocity ingest on the callback surface and nothing else, and a process with no bound listener fails to boot. Enable the callback listener, or disable the consumer tier and ingest through Kafka from a tier that has one." -}}
        {{- end -}}
        {{- $surfaces = list "callback" -}}
      {{- else -}}
        {{- $surfaces = list "console" -}}
      {{- end -}}
      {{/*
        Migrations and grants belong to the login that holds the admin role, and
        exactly one tier runs them. Every other tier is explicitly told not to,
        so a check replica scaling up does not try to migrate with a login that
        cannot.
      */}}
      {{- $migrates := eq $role "api" -}}
      {{- $tiers = append $tiers (dict
          "name" $role
          "roles" $role
          "tier" $spec
          "surfaces" $surfaces
          "credential" (index $top.Values.database.credentials $role)
          "migrate" (and $migrates $top.Values.database.migrate)
          "applyGrants" (and $migrates $top.Values.database.applyGrants)) -}}
    {{- end -}}
  {{- end -}}
  {{- if not $tiers -}}
    {{- fail "topology=split with every tier disabled renders nothing. Enable at least one entry under roles." -}}
  {{- end -}}
{{- else -}}
  {{- fail (printf "topology is %q, want \"all-in-one\" or \"split\"" .Values.topology) -}}
{{- end -}}
{{- $tiers | toYaml -}}
{{- end -}}

{{/*
The workload name of a tier. The all-in-one tier keeps the release name; a split
tier is suffixed with its role, which is also how its Service is found.
*/}}
{{- define "stamp.tierName" -}}
{{- $ctx := .ctx -}}
{{- if eq .tier.name "all" -}}
{{- include "stamp.fullname" $ctx -}}
{{- else -}}
{{- printf "%s-%s" (include "stamp.fullname" $ctx) .tier.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "stamp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "stamp.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .tier.name }}
{{- end -}}

{{/*
The listen address for one surface on one tier: a port when the tier binds it,
and the empty string when it does not.

The empty string is load-bearing. An absent variable makes the binary bind that
surface to its default, so "not listed" and "not served" are different things,
and the chart has to say the second one out loud.
*/}}
{{- define "stamp.addr" -}}
{{- $surface := .surface -}}
{{- if has $surface .tier.surfaces -}}
{{- printf ":%v" (index .ctx.Values.listeners $surface).port -}}
{{- end -}}
{{- end -}}

{{/*
The mount path of a configuration document. The value of the environment
variable is this path, never the document.
*/}}
{{- define "stamp.documentPath" -}}
{{- printf "/etc/stamp/documents/%s" .key -}}
{{- end -}}
