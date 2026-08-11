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

  check     PEP (AuthZEN evaluation)
  decide    PEP (decision create and the creator's read), console (approvals,
            inbox, audit views) and callback (MFA return, external challenge
            completion)
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
        {{- $surfaces = list "pep" "console" -}}
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

{{/*
stamp.documentEnv maps a documents.* setting to the variable the binary reads
it from. It is the one place the six names are listed, and an unknown name is
refused here rather than rendered into a manifest nothing would read.
*/}}
{{- define "stamp.documentEnv" -}}
{{- $names := dict
    "factSources" "STAMP_FACT_SOURCES"
    "streamSources" "STAMP_STREAM_SOURCES"
    "ingestCredentials" "STAMP_INGEST_CREDENTIALS"
    "externalTargets" "STAMP_EXTERNAL_TARGETS"
    "idpGroupSources" "STAMP_IDP_GROUP_SOURCES"
    "kafkaTopics" "STAMP_KAFKA_TOPICS" -}}
{{- $env := index $names . -}}
{{- if not $env -}}
{{- fail (printf "documents.%s is not a setting this chart knows" .) -}}
{{- end -}}
{{- $env -}}
{{- end -}}

{{/*
stamp.tierRuns reports whether a tier runs one role. The all-in-one tier runs
every one of them, which is what --roles=all means.
*/}}
{{- define "stamp.tierRuns" -}}
{{- if or (eq .tier.name "all") (eq .tier.name .role) -}}true{{- end -}}
{{- end -}}

{{/*
stamp.tierIssuesChallenges reports whether a tier can open a challenge, and so
whether it presents an external target's shared secret or the CIBA client's
credentials.

Two roles can, and the chart follows internal/runtime/credentials.go rather than
guessing: the decide role issues when a decision is created, and the api role
re-issues during the revalidation that applying a revision performs
(internal/decision/revalidate.go). An api tier without them would fail at the
moment a governance change landed.
*/}}
{{- define "stamp.tierIssuesChallenges" -}}
{{- if or (include "stamp.tierRuns" (dict "tier" .tier "role" "decide"))
          (include "stamp.tierRuns" (dict "tier" .tier "role" "api")) -}}true{{- end -}}
{{- end -}}

{{/*
stamp.tierReadsDocument reports whether one tier mounts one configuration
document (R42, R39).

The two credential-only documents follow their consumer. The ingest grants
authenticate an event producer against the ingest route, which only the consumer
role mounts; the external targets carry the webhook signing secret, which only a
tier that issues a challenge presents.

The other four reach every tier, and that is a property of the binary rather
than a shortcut. Every process loads the policy set at boot and the schema gate
refuses a source of a kind no plane in the process answers for, so the documents
that carry *declarations* have to be readable wherever a snapshot is loaded —
which is everywhere. The group sources are the awkward case: one document holds
both the declarations and the directory credential, so it stays on every tier,
and the narrowing there happens inside the binary instead (idpgroup.Gate, for
the roles that never call a directory).
*/}}
{{- define "stamp.tierReadsDocument" -}}
{{- if eq .document "ingestCredentials" -}}
{{- include "stamp.tierRuns" (dict "tier" .tier "role" "consumer") -}}
{{- else if eq .document "externalTargets" -}}
{{- include "stamp.tierIssuesChallenges" (dict "tier" .tier) -}}
{{- else -}}
true
{{- end -}}
{{- end -}}

{{/*
Audit checkpoints (R32, R42).

The directories are constants rather than settings. The key directory is a
read-only Secret mount and the sink directory is the one writable path in the
container, and both of those are properties of the pod this chart writes — an
operator who could move them could move the sink somewhere
readOnlyRootFilesystem makes unwritable and learn about it from a crash loop.
*/}}
{{- define "stamp.checkpointKeyDir" -}}/etc/stamp/checkpoint{{- end -}}
{{- define "stamp.checkpointVerifyDir" -}}/etc/stamp/checkpoint/verify{{- end -}}
{{- define "stamp.checkpointSinkDir" -}}/var/lib/stamp/checkpoints{{- end -}}

{{- define "stamp.checkpointKeyPath" -}}
{{- printf "%s/%s" (include "stamp.checkpointKeyDir" .) .Values.audit.checkpoint.signingKey.key -}}
{{- end -}}

{{- define "stamp.checkpointSinkPath" -}}
{{- printf "%s/%s" (include "stamp.checkpointSinkDir" .) .Values.audit.checkpoint.sink.file.name -}}
{{- end -}}

{{/*
The retired public halves, in the binary's "key-id=/path,other-id=/path" form.
Paths, not keys — the two halves of one rotation are configured the same way so
that nobody has to remember which of them is a literal.
*/}}
{{- define "stamp.checkpointVerifyKeys" -}}
{{- $dir := include "stamp.checkpointVerifyDir" . -}}
{{- $out := list -}}
{{- range $entry := .Values.audit.checkpoint.verifyKeys.keys -}}
{{- if not $entry.id -}}
{{- fail "stamp chart: an audit.checkpoint.verifyKeys.keys entry has no id. A checkpoint names the key it was signed under, and a public key with no identifier answers for nothing." -}}
{{- end -}}
{{- $out = append $out (printf "%s=%s/%s" $entry.id $dir $entry.key) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}

{{/*
stamp.tierRecordsCheckpoints reports whether one tier is the one that signs.

It is the api role and only it, and the chart follows the composition root
rather than offering a choice: internal/runtime/wiring.go registers the
checkpointer with Roles: []Role{RoleAPI}. Every other tier gets no checkpoint
environment and no signing key, which is the point — the key is mounted where it
is used and nowhere else.
*/}}
{{- define "stamp.tierRecordsCheckpoints" -}}
{{- if or (eq .tier.name "all") (eq .tier.name "api") -}}true{{- end -}}
{{- end -}}

{{/*
stamp.checkpointsValidated is the render-time refusal.

A release that asks for checkpoints and runs no api role produces a valid
manifest, starts healthily and records nothing: `stamp audit verify` has nothing
to check the log against, and the operator who wrote a signing key into these
values has every reason to believe otherwise. That belief is the failure — a
control that is absent is recoverable, and one that is believed present and is
not is not — so it is refused here rather than warned about. helm template does
not print NOTES.txt, and a warning nobody renders is not a warning.

Disabling the api tier is otherwise legitimate: a data-plane-only release
alongside a second release that runs api is a real shape. That release sets
audit.checkpoint.enabled: false and the release with the api tier takes the
checkpoints for the installation, which is what the remedy says.
*/}}
{{- define "stamp.checkpointsValidated" -}}
{{- $cp := .Values.audit.checkpoint -}}
{{- if $cp.enabled -}}
  {{- if not $cp.keyId -}}
    {{- fail "stamp chart: audit.checkpoint.enabled is set but audit.checkpoint.keyId is empty. Every checkpoint records the key it was signed under, and a key with no identifier cannot be rotated without invalidating everything the previous one signed, so the binary refuses to boot without it." -}}
  {{- end -}}
  {{- if not $cp.signingKey.secretName -}}
    {{- fail "stamp chart: audit.checkpoint.enabled is set but audit.checkpoint.signingKey.secretName is empty. The signing key arrives as a mounted Secret and never as a value (R42), so there is nothing to mount and the checkpointer would have no key." -}}
  {{- end -}}
  {{- if and (not $cp.sink.file.enabled) (not $cp.sink.webhook) -}}
    {{- fail "stamp chart: audit.checkpoint.enabled is set but no sink is. A checkpoint that never leaves the database is signed by a key the database does not hold and stored where the database can overwrite it. Enable audit.checkpoint.sink.file, or name a webhook." -}}
  {{- end -}}
  {{- if $cp.verifyKeys.keys -}}
    {{- if not $cp.verifyKeys.secretName -}}
      {{- fail "stamp chart: audit.checkpoint.verifyKeys.keys are listed but audit.checkpoint.verifyKeys.secretName is empty. The retired public halves are mounted from one Secret; there is nothing to mount them from." -}}
    {{- end -}}
  {{- end -}}
  {{- $tiers := include "stamp.tiers" . | fromYamlArray -}}
  {{- $records := false -}}
  {{- range $tier := $tiers -}}
    {{- if include "stamp.tierRecordsCheckpoints" (dict "tier" $tier) -}}{{- $records = true -}}{{- end -}}
  {{- end -}}
  {{- if not $records -}}
    {{- fail "stamp chart: audit.checkpoint.enabled is set and this release runs no api role, so nothing in it records a checkpoint. internal/runtime/wiring.go registers the checkpointer under the api role alone, so this release would render valid manifests, start healthy, publish no signed copy of its audit chain, and leave `stamp audit verify` with nothing to check the log against. Either set roles.api.enabled: true here, or set audit.checkpoint.enabled: false and configure checkpoints on the release that does run the api role." -}}
  {{- end -}}
{{- end -}}
{{- end -}}
