/**
 * The inbox routes.
 *
 * Two of them: the list and one approval. The approval carries the decision
 * identifier and the challenge ordinal in the path rather than in state,
 * because an approver forwards that link to a colleague and because the same
 * pair is what the audit row, the API path and the console URL all say.
 */
import { Route, Routes } from 'react-router-dom'
import { ApprovalScreen } from './ApprovalScreen'
import { InboxScreen } from './InboxScreen'
import { NotFoundScreen } from '../app/screens'
import '../diff/diff.css'
import './inbox.css'

export function InboxRoutes() {
  return (
    <Routes>
      <Route index element={<InboxScreen />} />
      <Route path=":decisionId/:ordinal" element={<ApprovalScreen />} />
      <Route path="*" element={<NotFoundScreen />} />
    </Routes>
  )
}
