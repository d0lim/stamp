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
import { NoAccessScreen, NotFoundScreen } from './screens'
import { PolicyRoutes } from '../builder/routes'
import { AuditRoutes } from '../audit/routes'
import { InboxRoutes } from '../inbox/routes'
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
                <PolicyRoutes />
              </RequireRole>
            </AuthGate>
          }
        />
        <Route
          path="/inbox/*"
          element={
            <AuthGate>
              <RequireRole role="approver">
                <InboxRoutes />
              </RequireRole>
            </AuthGate>
          }
        />
        {/*
          The audit subtree guards its own routes rather than being guarded as
          one. R22 lets a reader without auditor standing open a decision they
          created or are a target of, so the history is behind the role and one
          decision is not — see audit/routes.tsx.
        */}
        <Route
          path="/audit/*"
          element={
            <AuthGate>
              <AuditRoutes />
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
