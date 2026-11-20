// ============================================================
// 文件名称：protocols.js
// 生成日期：2026-10-22
// 修改日期：2026-11-20
// 版本信息：v0.261115
// 作    者：JUN
// 备    注：本程序由AI辅助完成。
//           文件功能：实现 protocols 模块相关功能。
//           文件用途：供堡垒机的 leizhang/static/protocols.js 模块使用。
//           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
// ============================================================
'use strict';
const protocolNames={ssh:'SSH',telnet:'TELNET',rdp:'RDP',vnc:'VNC',http:'HTTP / HTTPS',postgresql:'PostgreSQL',mysql:'MySQL / MariaDB'};
const protocolPorts={ssh:22,telnet:23,rdp:3389,vnc:5900,http:80,postgresql:5432,mysql:3306};
function protocolSocket(result){
 const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+result.websocket);
 socket=ws;ws.onopen=()=>ws.send(JSON.stringify({ticket:result.ticket}));return ws;
}
function sendProtocol(ws,message){if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(message));}
function guacView(parent,ws=null){
 const tunnel=new Guacamole.Tunnel(),parser=new Guacamole.Parser();
 tunnel.connect=()=>{};tunnel.disconnect=()=>ws?.close();
 tunnel.sendMessage=(...parts)=>{if(ws?.readyState===WebSocket.OPEN)ws.send(parts.map(p=>{p=String(p);return Array.from(p).length+'.'+p;}).join(',')+';');};
 parser.oninstruction=(opcode,args)=>tunnel.oninstruction?.(opcode,args);
 const client=new Guacamole.Client(tunnel),display=client.getDisplay(),element=display.getElement();
 const box=node('div',undefined,'remote-display');box.tabIndex=0;box.append(element);parent.append(box);
 client.onerror=error=>notify('远程桌面：'+error.message);
 client.connect();
 const fit=()=>display.scale(Math.min(1,(box.clientWidth||1280)/(display.getWidth()||1280)));
 display.onresize=fit;
 if(ws){
  const keyboard=new Guacamole.Keyboard(box),mouse=new Guacamole.Mouse(element);
  keyboard.onkeydown=key=>{client.sendKeyEvent(1,key);return false;};keyboard.onkeyup=key=>client.sendKeyEvent(0,key);
  mouse.onEach(['mousedown','mouseup','mousemove'],event=>client.sendMouseState(event.state,true));
  box.onpointerdown=()=>box.focus();box.onblur=()=>keyboard.reset();
  window.protocolCleanup=()=>{keyboard.reset();client.disconnect();};
 }
 return {feed:raw=>parser.receive(raw),client};
}
async function connectProtocol(asset,result){
 const c=openModal((protocolNames[result.protocol]||result.protocol)+' · '+asset.name+' / '+result.system_username);
 const status=node('p','正在连接…','muted');c.append(status);
 if(result.protocol==='vnc'){
  const state=await api('/protocol-status');
  if(state.vnc_native){status.remove();const view=nativeVncView(c,result);window.protocolCleanup=()=>view.close();return;}
 }
 if(['rdp','vnc'].includes(result.protocol)){
  const state=await api('/protocol-status');if(!state.desktop_gateway){status.textContent=state.desktop_message;await api('/sessions/'+result.id+'/terminate','POST',{});return;}
  const ws=protocolSocket(result),view=guacView(c,ws);
  status.textContent='鼠标点击画面后可操作。画面加密录制，关闭窗口断开。';
  ws.onmessage=e=>{if(e.data.startsWith('{')){const m=JSON.parse(e.data);if(m.type==='closed')status.textContent=m.message;}else view.feed(e.data);};
  ws.onclose=()=>{status.textContent+=' [连接已断开]';};return;
 }
 const ws=protocolSocket(result);
 ws.onclose=()=>{status.textContent+=' [连接已断开]';};
 if(['postgresql','mysql'].includes(result.protocol)){
  c.append(node('p','本控制台中的 SQL 会被审计。每次执行一条语句；写入操作立即提交。最多展示 500 行。','muted'));
  const sql=node('textarea',undefined,'sql-editor');sql.setAttribute('aria-label','SQL 语句');sql.placeholder='SELECT 1;';
  const output=node('div'),execute=button('执行 SQL',()=>{if(!sql.value.trim())throw Error('请输入 SQL');if(ws.readyState!==WebSocket.OPEN)throw Error('连接未就绪');execute.disabled=true;sendProtocol(ws,{type:'query',sql:sql.value});});
  // button() restores enabled after its callback, so use a distinct busy flag.
  let busy=false;execute.onclick=()=>{if(busy||ws.readyState!==WebSocket.OPEN)return;if(!sql.value.trim()){notify('请输入 SQL');return;}busy=true;execute.disabled=true;sendProtocol(ws,{type:'query',sql:sql.value});};
  execute.disabled=true;c.append(sql);actions(c,execute);c.append(output);
  ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='ready'){status.textContent=m.message;execute.disabled=false;}if(m.type==='closed'){status.textContent=m.message;execute.disabled=true;}if(m.type==='result'){busy=false;execute.disabled=false;output.replaceChildren(node('p',m.error||('执行成功 · '+m.elapsed_ms+' ms · '+m.row_count+' 行'+(m.truncated?'（展示已截断）':''))));if(m.columns?.length)output.append(table(m.rows.map(row=>Object.fromEntries(row.map((v,i)=>['c'+i,v]))),m.columns.map((v,i)=>['c'+i,v])));}};
  return;
 }
 const image=node('img',undefined,'remote-browser');image.alt='HTTP 远程浏览器';image.tabIndex=0;
 const path=node('input');path.value=asset.http_path||'/';path.setAttribute('aria-label','当前资源站内路径');
 actions(c,path,button('打开路径',()=>sendProtocol(ws,{type:'navigate',path:path.value})));
 c.append(image);image.onclick=e=>{const r=image.getBoundingClientRect();sendProtocol(ws,{type:'click',x:(e.clientX-r.left)*1280/r.width,y:(e.clientY-r.top)*720/r.height});image.focus();};
 image.onwheel=e=>{e.preventDefault();sendProtocol(ws,{type:'wheel',delta:e.deltaY});};
 image.onkeydown=e=>{e.preventDefault();if(e.key.length===1&&!e.ctrlKey&&!e.metaKey)sendProtocol(ws,{type:'text',text:e.key});else if(['Enter','Tab','Backspace','Delete','Escape','ArrowUp','ArrowDown','ArrowLeft','ArrowRight','Home','End','PageUp','PageDown'].includes(e.key))sendProtocol(ws,{type:'key',key:e.key});};
 const text=node('textarea');text.setAttribute('aria-label','向远程页面输入文字');text.placeholder='可粘贴中文或多行文本，然后点击发送';
 c.append(text);actions(c,button('发送文字',()=>{sendProtocol(ws,{type:'text',text:text.value});text.value='';}));
 ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='frame'){image.src='data:image/jpeg;base64,'+m.data;}else if(m.message)status.textContent=m.message;};
}
async function protocolAuditView(root,sessionId='',commandsOnly=false){
 const commandActions={command_requested:'提交命令',command_denied:'拒绝执行',command_completed:'执行结束',command_forwarded:'已转发（TELNET）'};
 let page=1,protocol='',generation=0;const data=node('div');
 const load=async()=>{const own=++generation;const rows=await api('/protocol-audit?page='+page+'&session_id='+encodeURIComponent(sessionId)+'&protocol='+encodeURIComponent(protocol)+(commandsOnly?'&action_group=command':''));if(own!==generation)return;notify('');
 data.replaceChildren(table(rows,[['created_at','时间'],['username','操作者'],['asset','资源'],['system_username','系统账号'],['protocol','协议'],['action','事件',r=>node('span',commandActions[r.action]||r.action)],['success','成功'],['elapsed_ms','耗时 ms'],['row_count','影响行数'],['operation_id','关联操作'],['detail','详情',r=>node('pre',JSON.stringify(r.detail,null,2),'audit-detail')]]));};
 const filters=form(root,[['protocol','协议','select','',[['','全部'],...Object.entries(protocolNames).filter(([key])=>!commandsOnly||['ssh','telnet'].includes(key))]]],async values=>{protocol=values.protocol;page=1;await load();},'筛选');
 filters.protocol.closest('form').classList.add('protocol-audit-filters');
 actions(root,button('上一页',async()=>{page=Math.max(1,page-1);await load();},'secondary'),button('下一页',async()=>{page++;await load();},'secondary'),button('刷新',load,'secondary'));
 root.append(data);await load();
}
async function replayProtocol(row){
 const c=openModal('会话审计 / 录像 · '+row.asset);
 if(['postgresql','mysql'].includes(row.protocol)){await protocolAuditView(c,row.id);return;}
 const events=await api('/sessions/'+row.id+'/recording');
 if(!events.length){c.append(node('p','暂无录像'));return;}
 let feed;
 if(row.protocol==='http'||(row.protocol==='vnc'&&events[0].data.trim().startsWith('{'))){const image=node('img',undefined,'remote-browser');image.alt='远程画面录像';c.append(image);feed=raw=>{const m=JSON.parse(raw);image.src='data:image/jpeg;base64,'+m.data;};}
 else {const view=guacView(c);feed=view.feed;window.protocolCleanup=()=>view.client.disconnect();}
 const status=node('p','按原始时间回放，关闭窗口停止。','muted');c.append(status);
 actions(c,button('开始回放',()=>{for(const t of replayTimers)clearTimeout(t);replayTimers=[];for(const event of events)replayTimers.push(setTimeout(()=>feed(event.data),event.ms));}));
}
