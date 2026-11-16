import App from './App.svelte'
import './app.css'

const appearance=localStorage.getItem('openppp2-appearance') || 'system'
document.documentElement.dataset.theme=appearance === 'light' || appearance === '浅色' ? 'light' : appearance === 'dark' || appearance === '深色' ? 'dark' : matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'

const app = new App({
  target: document.getElementById('app'),
})

export default app
