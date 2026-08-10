/**
 * The builder's routes, mounted under the shell's `/policies/*` seam.
 *
 * The shell owns who may reach this subtree — the author role, checked in
 * App.tsx — so nothing here re-checks it. Two screens: the effective set, and
 * the authoring flow.
 */
import { Route, Routes } from 'react-router-dom'
import { BuilderScreen } from './BuilderScreen'
import { PolicyListScreen } from './PolicyListScreen'
import './builder.css'

export function PolicyRoutes() {
  return (
    <Routes>
      <Route index element={<PolicyListScreen />} />
      <Route path="new" element={<BuilderScreen />} />
      <Route path="*" element={<PolicyListScreen />} />
    </Routes>
  )
}
