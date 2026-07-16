import React from 'react'
import ReactDOM from 'react-dom/client'
import { App } from './App'
import { installDemoApi } from './demo'
import './styles.css'

if (import.meta.env.VITE_DEMO === 'true') installDemoApi()

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
