<script>
  import { onDestroy, onMount } from 'svelte'
  import Sidebar from './lib/components/Sidebar.svelte'
  import Topbar from './lib/components/Topbar.svelte'
  import Connection from './routes/Connection.svelte'
  import Nodes from './routes/Nodes.svelte'
  import Subscription from './routes/Subscription.svelte'
  import Logs from './routes/Logs.svelte'
  import Settings from './routes/Settings.svelte'
  import Routing from './routes/Routing.svelte'
  import Dns from './routes/Dns.svelte'
  import { language } from './lib/i18n.js'
  import { createRuntime } from './lib/runtime/index.js'

  const runtime = createRuntime()
  let state
  let unsubscribe
  let startupError = ''
  let initialized=runtime.kind === 'demo'
  let systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  $: if (state) language.set(state.settings.language)
  $: theme = state?.settings.appearance || 'system'
  $: if(state && initialized) { localStorage.setItem('openppp2-appearance',theme); document.documentElement.lang=state.settings.language === 'English' ? 'en' : 'zh-CN' }
  $: if(initialized) document.documentElement.dataset.theme = theme === 'light' || theme === '浅色' ? 'light' : theme === 'dark' || theme === '深色' ? 'dark' : systemDark ? 'dark' : 'light'

  function handleKeydown(event) {
    if (!(event.ctrlKey || event.metaKey)) return
    const key = event.key.toLowerCase()
    if (key === 'k') {
      event.preventDefault()
      runtime.navigate('nodes')
    }
    if (key === 'd') {
      event.preventDefault()
      if (state.connection.status === 'connected') runtime.disconnect()
      else runtime.connect()
    }
  }

  onMount(() => {
    unsubscribe = runtime.subscribe((next) => (state = next))
    window.addEventListener('keydown', handleKeydown)
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const update = (event) => { systemDark = event.matches }
    media.addEventListener('change', update)
    runtime.ready?.then(() => initialized=true).catch((error) => { startupError = String(error) })
    return () => media.removeEventListener('change', update)
  })

  onDestroy(() => {
    unsubscribe?.()
    window.removeEventListener('keydown', handleKeydown)
  })
</script>

{#if state}
  <div class="shell">
    <Sidebar current={state.route} navigate={(route) => runtime.navigate(route)} version={state.kernel?.version} />
    <main>
      <Topbar {state} {runtime} />
      <div class="content">
        {#if startupError}<div role="alert" class="notice">{startupError}</div>{/if}
        {#if state.route === 'connection'}
          <Connection {state} {runtime} />
        {:else if state.route === 'nodes'}
          <Nodes {state} {runtime} />
        {:else if state.route === 'subscription'}
          <Subscription {state} {runtime} />
        {:else if state.route === 'logs'}
          <Logs {state} {runtime} />
        {:else if state.route === 'routing'}
          <Routing {state} {runtime} />
        {:else if state.route === 'dns'}
          <Dns {state} {runtime} />
        {:else if state.route === 'settings'}
          <Settings {state} {runtime} />
        {/if}
      </div>
    </main>
  </div>
{/if}

<style>
  .shell { min-height: 100vh; display: grid; grid-template-columns: 196px minmax(0, 1fr); }
  main { min-width: 0; padding: 0 24px 18px; }
  .content { max-width: 1100px; margin: 0; }
  @media (max-width: 900px) { .shell { grid-template-columns: 58px minmax(0,1fr); } main { padding: 0 16px 18px; } }
  @media (max-width: 560px) { .shell { grid-template-columns:58px minmax(0,1fr); } main { padding:0 10px 24px; } }
</style>
