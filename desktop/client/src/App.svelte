<script>
  import { onDestroy, onMount } from 'svelte'
  import Sidebar from './lib/components/Sidebar.svelte'
  import Topbar from './lib/components/Topbar.svelte'
  import Connection from './routes/Connection.svelte'
  import Nodes from './routes/Nodes.svelte'
  import Subscription from './routes/Subscription.svelte'
  import Logs from './routes/Logs.svelte'
  import Config from './routes/Config.svelte'
  import Settings from './routes/Settings.svelte'
  import { createRuntime } from './lib/runtime/index.js'

  const runtime = createRuntime()
  let state
  let unsubscribe

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
  })

  onDestroy(() => {
    unsubscribe?.()
    window.removeEventListener('keydown', handleKeydown)
  })
</script>

{#if state}
  <div class="shell">
    <Sidebar current={state.route} navigate={(route) => runtime.navigate(route)} />
    <main>
      <Topbar {state} {runtime} />
      <div class="content">
        {#if state.route === 'connection'}
          <Connection {state} {runtime} />
        {:else if state.route === 'nodes'}
          <Nodes {state} {runtime} />
        {:else if state.route === 'subscription'}
          <Subscription {state} {runtime} />
        {:else if state.route === 'logs'}
          <Logs {state} {runtime} />
        {:else if state.route === 'config'}
          <Config {state} {runtime} />
        {:else if state.route === 'settings'}
          <Settings {state} {runtime} />
        {/if}
      </div>
      <footer><span>Ctrl+K 节点</span><span>Ctrl+D 断开 / 连接</span></footer>
    </main>
  </div>
{/if}

<style>
  .shell { min-height: 100vh; display: grid; grid-template-columns: 196px minmax(0, 1fr); }
  main { min-width: 0; padding: 0 24px 18px; }
  .content { max-width: 872px; margin: 0; }
  footer { margin: 24px 0 0; display: flex; justify-content: space-between; color: #536171; font-size: 10px; }
  @media (max-width: 900px) { .shell { grid-template-columns: 58px minmax(0,1fr); } main { padding: 0 16px 18px; } }
  @media (max-width: 560px) { .shell { display: block; } main { padding: 0 10px 72px; } footer { display: none; } }
</style>
