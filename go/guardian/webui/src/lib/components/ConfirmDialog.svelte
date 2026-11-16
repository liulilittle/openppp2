<script>
  import { t } from '../i18n.js'
  export let open = false
  export let title = t('confirm')
  export let message = t('confirmDelete')
  export let confirmText = t('confirm')
  export let cancelText = t('cancel')
  export let tone = 'danger'

  import { createEventDispatcher } from 'svelte'
  const dispatch = createEventDispatcher()

  function close() {
    dispatch('cancel')
  }

  function confirm() {
    dispatch('confirm')
  }
</script>

{#if open}
  <div class="overlay" role="presentation" on:click|self={close}>
    <div class="dialog" role="dialog" aria-modal="true">
      <h3>{title}</h3>
      <p>{message}</p>
      <div class="actions">
        <button class="secondary" on:click={close}>{cancelText}</button>
        <button class:tone-danger={tone === 'danger'} class:tone-accent={tone !== 'danger'} on:click={confirm}>{confirmText}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(1, 4, 9, 0.7);
    display: grid;
    place-items: center;
    z-index: 40;
  }

  .dialog {
    width: min(420px, calc(100vw - 2rem));
    padding: 1.25rem;
    border-radius: 14px;
    border: 1px solid #30363d;
    background: #161b22;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
  }

  h3 {
    margin: 0 0 0.75rem;
    font-size: 1.05rem;
  }

  p {
    margin: 0;
    color: #8b949e;
    line-height: 1.5;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.75rem;
    margin-top: 1.25rem;
  }

  button {
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 1rem;
    color: #c9d1d9;
    background: #21262d;
    cursor: pointer;
  }

  .secondary:hover {
    background: #262c36;
  }

  .tone-danger {
    background: #f85149;
    border-color: #f85149;
    color: white;
  }

  .tone-accent {
    background: #238636;
    border-color: #238636;
    color: white;
  }
</style>
