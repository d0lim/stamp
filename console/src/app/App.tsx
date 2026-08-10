/**
 * The route table.
 *
 * The callback route sits outside the auth gate — it is how a session comes to
 * exist — and everything else sits inside it. The landing route is a redirect
 * derived from the token's roles rather than a screen, so "where do I land"
 * has one implementation and U15 and U16 do not each get a say in it.
 */
import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthGate } from './AuthGate'
import { CallbackScreen } from './CallbackScreen'
import { Layout } from './Layout'
import { RequireRole } from './RequireRole'
import {
  AuditScreen,
  InboxScreen,
  NoAccessScreen,
  NotFoundScreen,
  PoliciesScreen,
} from './screens'
import { useAuth } from '../auth/AuthProvider'

function Landing() {
  const { landing } = useAuth()
  return <Navigate to={landing} replace />
}

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/callback" element={<CallbackScreen />} />
        <Route
          path="/"
          element={
            <AuthGate>
              <Landing />
            </AuthGate>
          }
        />
        <Route
          path="/policies/*"
          element={
            <AuthGate>
              <RequireRole role="author">
                <PoliciesScreen />
              </RequireRole>
            </AuthGate>
          }
        />
        <Route
          path="/inbox/*"
          element={
            <AuthGate>
              <RequireRole role="approver">
                <InboxScreen />
              </RequireRole>
            </AuthGate>
          }
        />
        <Route
          path="/audit/*"
          element={
            <AuthGate>
              <RequireRole role="auditor">
                <AuditScreen />
              </RequireRole>
            </AuthGate>
          }
        />
        <Route
          path="/no-access"
          element={
            <AuthGate>
              <NoAccessScreen />
            </AuthGate>
          }
        />
        <Route
          path="*"
          element={
            <AuthGate>
              <NotFoundScreen />
            </AuthGate>
          }
        />
      </Route>
    </Routes>
  )
}
