<script>
  import ConnectionHero from '../lib/components/ConnectionHero.svelte'
  import StatsPanel from '../lib/components/StatsPanel.svelte'
  import EventList from '../lib/components/EventList.svelte'
  import NodeTable from '../lib/components/NodeTable.svelte'
  export let state
  export let runtime
  $: commonNodes = state.subscription.nodes.slice(0, 4)
</script>

<div class="page">
  <ConnectionHero {state} {runtime} />
  {#if state.connection.statsAvailable}<StatsPanel stats={state.stats} />{/if}
  <EventList events={state.events} onAll={() => runtime.navigate('logs')} />
  <section class="panel">
    <div class="panel-head"><h2 class="panel-title">常用节点</h2><button class="inline-link" on:click={() => runtime.navigate('nodes')}>全部节点 →</button></div>
    <NodeTable nodes={commonNodes} currentNodeId={state.connection.currentNodeId} {runtime} />
  </section>
</div>
