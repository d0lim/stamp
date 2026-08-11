package runtime

// credentials.go answers the question the composition root used to not ask:
// which of this deployment's secrets does *this* process have any use for.
//
// R42's second clause is the one that was open. Every secret already arrives by
// file or Secret reference, but "and is not present where it is not needed" was
// untrue of four of them: a check tier held the webhook signing keys, the CIBA
// client secret and the ingest grants because the graph was built before roles
// were applied. R39's promise is that a tier compromised through the PEP
// surface holds credentials it cannot write policy with, and the database side
// keeps it — separate login, separate grants — while the file side handed it
// back.
//
// The rules are stated here rather than inline because the chart has to state
// the same ones, and two statements of one rule in two languages is a pair that
// drifts. deploy/helm/stamp/templates/_helpers.tpl names this file.
//
// What is *not* here is as load-bearing. The declaration documents — fact
// sources, velocity sources, group sources — reach every tier whatever its
// roles, because every process loads the policy set at boot and the schema gate
// refuses a kind no plane in the process answers for. Narrowing those would not
// be a smaller blast radius, it would be a tier that cannot start. The gate a
// non-calling process gets instead is [idpgroup.Gate]: the same verification,
// from the same code, holding no credential and dialling nothing.

// issuesChallenges reports whether these roles can open a challenge, and so
// whether this process presents an external target's shared secret or the CIBA
// client's credentials.
//
// Two roles can, not one. The decide role is the obvious one — creating a
// decision is what issues challenges. The api role is the one that is easy to
// miss: applying a revision revalidates the decisions still open under it, and
// [decision.Revalidator] re-issues a challenge whose binding moved
// (internal/decision/revalidate.go). The reconcile loop that drives it runs
// under RoleAPI, so an api tier without the targets would fail a revalidation
// at the moment a governance change landed — which is the worst moment for a
// deployment to discover a missing credential.
func issuesChallenges(roles Set) bool {
	return roles.Has(RoleDecide) || roles.Has(RoleAPI)
}

// callsDirectories reports whether these roles ever resolve an idp_group
// source, and so whether this process holds the directory credential.
//
// Three roles do. Check and decide resolve them from conditions; decide also
// resolves an approver set from one; and api evaluates on the dry-run path and
// resolves sources during revalidation. The consumer and console roles do
// neither, and get [idpgroup.Gate] instead — which still refuses every schema
// the calling roles refuse.
func callsDirectories(roles Set) bool {
	return roles.Has(RoleCheck) || roles.Has(RoleDecide) || roles.Has(RoleAPI)
}

// withoutUnusedCredentials returns cfg with every credential these roles never
// present removed.
//
// It runs after [Config.validate], so a misconfiguration is still reported by
// every tier that reads it, and before anything is constructed, so a credential
// a role does not use is never handed to a component that could spend it. The
// clearing is by whole setting rather than by field: a process that issues no
// challenge has no more use for a webhook destination than for the key it would
// sign the call with, and a CIBA client with its endpoints and no secret is a
// configuration [mfa.NewCIBA] refuses outright.
//
// The group sources are not cleared. Their document carries the declarations
// the schema gate is built from as well as the credential, and a tier with
// neither could not load a policy set that names one; the role split for them
// is [callsDirectories] choosing a gate over a caller.
func withoutUnusedCredentials(cfg Config, roles Set) Config {
	if !issuesChallenges(roles) {
		cfg.ExternalTargets = nil
		cfg.MFA.CIBA = CIBAConfig{}
	}
	if !roles.Has(RoleConsumer) {
		cfg.IngestCredentials = nil
	}
	return cfg
}
