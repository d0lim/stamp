-- The audit console's query axes and the approver inbox, indexed.
--
-- The requirements deferred the audit console's query axes (period, policy,
-- subject, state) with their ordering, pagination and the indexes that serve
-- them to design time, and asked for the answer to land in this
-- directory. internal/store/history.go states the axes; these are the indexes
-- that make them a seek rather than a scan.
--
-- Every one of them carries `created_at DESC, id DESC` as its trailing columns,
-- because that pair is both the sort order and the keyset cursor: a page break
-- is a row-value comparison against exactly those columns, so an index that
-- ends in them turns "the next fifty rows after this one" into an index seek no
-- matter which axis narrowed the query first. `id` is in the key because
-- created_at is not unique — without it a page boundary between two decisions
-- created in the same microsecond is ambiguous and can drop a row.
--
-- Combining two axes (policy *and* subject) uses one of these and filters the
-- rest. That is the intended trade: a per-combination index is 2^4 indexes on a
-- table whose write path is the decision hot path, and the axes are narrow
-- enough individually that the residual filter is cheap.

-- The unfiltered timeline, which is also the axis a period-only query uses:
-- created_at leads, so a range on it is a bounded scan of this index.
CREATE INDEX decisions_history_idx ON decisions (created_at DESC, id DESC);

CREATE INDEX decisions_policy_history_idx ON decisions (policy_id, created_at DESC, id DESC);

CREATE INDEX decisions_subject_history_idx ON decisions (subject_id, created_at DESC, id DESC);

CREATE INDEX decisions_state_history_idx ON decisions (state, created_at DESC, id DESC);

-- The caller axis — R22's narrowing for a reader without auditor standing — is
-- already served by decisions_caller_idx (caller_id, created_at DESC) from
-- 000002. It is not redeclared here.

-- The inbox candidate join.
--
-- It is partial on exactly the rows an inbox can contain: a quorum challenge
-- still collecting. Those are bounded by the decisions currently open, because
-- a decision expires, so this index stays small while the history table it
-- joins against grows without limit. `detail` rides along as an INCLUDE column
-- so the member test — `detail -> 'members' @> …` — is answered from the index
-- rather than by visiting a heap tuple per candidate. A GIN index on the
-- membership expression was considered and rejected: it would be built over
-- every challenge row ever written to answer a question that only concerns the
-- open ones.
CREATE INDEX challenge_progress_open_quorum_idx
    ON challenge_progress (decision_id, ordinal) INCLUDE (detail)
    WHERE state = 'pending' AND kind = 'quorum';
