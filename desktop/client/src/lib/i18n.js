import { writable, derived } from 'svelte/store'
export const language = writable('简体中文')
export const t = derived(language, (locale) => (english, chinese = english) => locale === 'English' ? english : chinese)
