/**
 * The audit routes: the history, and one decision.
 *
 * The detail route is reachable by identifier alone, which is what makes R22's
 * second half usable — a person without auditor standing has no history to page
 * through, but they still have the decision they created or are waiting on, and
 * a link to it works.
 */
import { Route, Routes } from 'react-router-dom'
import { AuditDecisionScreen } from './AuditDecisionScreen'
import { AuditScreen } from './AuditScreen'
import { NotFoundScreen } from '../app/screens'
import { RequireRole } from '../app/RequireRole'
import './audit.css'

export function AuditRoutes() {
  return (
    <Routes>
      {/*
        The history needs auditor navigation; one decision does not. R22 gives a
        reader without auditor standing the decisions they created or are a
        target of, and a role guard on the detail route would take away the link
        that rule exists to make usable. The server authorises both either way.
      */}
      <Route
        index
        element={
          <RequireRole role="auditor">
            <AuditScreen />
          </RequireRole>
        }
      />
      <Route path=":decisionId" element={<AuditDecisionScreen />} />
      <Route path="*" element={<NotFoundScreen />} />
    </Routes>
  )
}
