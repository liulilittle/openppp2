import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createConnection } from 'node:net'
const listening=(port) => new Promise((done) => {
  const socket=createConnection({host:'127.0.0.1',port})
  const finish=(result) => { socket.destroy(); done(result) }
  socket.once('connect',() => finish(true)); socket.once('error',() => finish(false)); socket.setTimeout(500,() => finish(false))
})
const {chromium}=await import(pathToFileURL(resolve(process.env.PLAYWRIGHT_MODULE)).href)
const browser=await chromium.connectOverCDP('http://127.0.0.1:9223')
try {
  const page=browser.contexts()[0].pages().find((page) => page.url().includes('tauri')) || browser.contexts()[0].pages()[0]
  await page.waitForFunction(() => !!window.__TAURI__)
  const invoke=async (command,args={}) => {
    console.log(`Checking ${command}`)
    let timeout
    try {
      return await Promise.race([
        page.evaluate(({command,args}) => window.__TAURI__.core.invoke(command,args),{command,args}),
        new Promise((_,reject) => { timeout=setTimeout(() => reject(new Error(`${command} timed out`)),15000) })
      ])
    } finally { clearTimeout(timeout) }
  }
  let bootstrap=await invoke('client_bootstrap')
  for (const node of bootstrap.subscription.nodes) await invoke('client_delete_manual_node',{nodeId:node.id})
  await invoke('client_update_setting',{key:'pppPath',value:resolve('x64/Release/ppp.exe')})
  const info=await invoke('client_kernel_info')
  assert.match(info.version,/\d+\.\d+\.\d+/)
  await invoke('client_update_setting',{key:'connectionMode',value:'proxy'})
  await invoke('client_update_setting',{key:'autoSystemProxy',value:false})
  await invoke('client_update_network',{overrides:{dns:{servers:{domestic:'doh.pub',foreign:'cloudflare'}}}})
  const local=await invoke('client_upsert_manual_node',{node:{id:null,name:'Native QA',subtitle:'',config:{key:{'protocol-key':'qa-only','transport-key':'qa-only'},client:{server:'ppp://127.0.0.1:1/','http-proxy':{bind:'127.0.0.1',port:18081},'socks-proxy':{bind:'127.0.0.1',port:18082}}},options:{}}})
  const id=local.nodes[0].id
  const preview=await invoke('client_preview',{nodeId:id})
  assert.equal(preview.config.key['protocol-key'],'[redacted]')
  assert.equal(preview.config.dns.servers.domestic,'doh.pub')
  assert(preview.args.includes('--mode=proxy'))
  try {
    const first=await invoke('client_connect',{nodeId:id})
    assert(first.pid > 0 && first.sessionId > 0)
    await assert.rejects(invoke('client_connect',{nodeId:id}),/Disconnect/)
    await assert.rejects(invoke('client_delete_manual_node',{nodeId:id}),/先断开/)
    for(let attempt=0;attempt<30 && !(await listening(18081) && await listening(18082));attempt++) await page.waitForTimeout(200)
    assert(await listening(18081),'HTTP listener must be ready')
    assert(await listening(18082),'SOCKS listener must be ready')
    bootstrap=await invoke('client_bootstrap')
    for(let attempt=0;attempt<30 && !bootstrap.connection.stats;attempt++) {
      await page.waitForTimeout(200)
      bootstrap=await invoke('client_bootstrap')
    }
    assert.equal(bootstrap.connection.pid,first.pid)
    assert(bootstrap.connection.stats,'structured statistics must be present')
    assert.notEqual(bootstrap.connection.status,'connected','unreachable test server must not report a working VPN')
    await invoke('client_disconnect')
    bootstrap=await invoke('client_bootstrap')
    assert.equal(bootstrap.connection.pid,null)
    assert.equal(bootstrap.connection.status,'disconnected')
    assert.equal(await listening(18081),false)
    assert.equal(await listening(18082),false)
    const second=await invoke('client_connect',{nodeId:id})
    assert(second.sessionId > first.sessionId)
  } finally { await invoke('client_disconnect') }
  if (!bootstrap.administrator) {
    await invoke('client_update_setting',{key:'connectionMode',value:'client'})
    await assert.rejects(invoke('client_connect',{nodeId:id}),/administrator/)
    await invoke('client_update_setting',{key:'connectionMode',value:'proxy'})
  }
  await invoke('client_delete_manual_node',{nodeId:id})
  assert.equal((await invoke('client_bootstrap')).subscription.nodes.length,0)
  console.log(JSON.stringify({result:'Native Tauri smoke passed',version:info.version,statsSupported:info.statsSupported,checks:['bootstrap','kernel inspection','network save','manual node','redacted preview','real spawn','duplicate connect rejected','HTTP/SOCKS listeners','structured stats','disconnect releases ports','session generation','delete']}))
} finally { await browser.close() }
