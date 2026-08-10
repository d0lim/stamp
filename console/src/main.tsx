/**
 * Boot order: configuration first, everything else after.
 *
 * The console cannot render anything useful before it knows where its API is,
 * and the only place that answer comes from is the server that served this
 * bundle. Rendering first and configuring later would mean a window in which
 * some other value could take effect — which is exactly the window R50 exists
 * to close.
 */
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './app/App'
import { ConfigErrorScreen } from './app/ConfigErrorScreen'
import { AuthProvider } from './auth/AuthProvider'
import { ConfigError, loadRuntimeConfig } from './config/runtime-config'
import './styles.css'

const container = document.getElementById('root')
if (!container) throw new Error('#root가 문서에 없습니다.')
const root = createRoot(container)

void (async () => {
  try {
    const config = await loadRuntimeConfig()
    root.render(
      <StrictMode>
        <BrowserRouter basename={config.basePath}>
          <AuthProvider config={config}>
            <App />
          </AuthProvider>
        </BrowserRouter>
      </StrictMode>,
    )
  } catch (cause) {
    const error = cause instanceof ConfigError ? cause : null
    root.render(
      <StrictMode>
        <ConfigErrorScreen
          message={error?.message ?? '콘솔을 시작하지 못했습니다.'}
          {...(error?.detail ? { detail: error.detail } : {})}
        />
      </StrictMode>,
    )
  }
})()
