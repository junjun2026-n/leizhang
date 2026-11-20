// ============================================================
// 文件名称：vnc.js
// 生成日期：2026-10-26
// 修改日期：2026-11-20
// 版本信息：v0.261115
// 作    者：JUN
// 备    注：本程序由AI辅助完成。
//           文件功能：实现 vnc 模块相关功能。
//           文件用途：供堡垒机的 leizhang/static/vnc.js 模块使用。
//           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
// ============================================================
'use strict';
function nativeVncView(root,result){
 const status=node('p','正在直接连接 VNC…','muted'),image=node('img',undefined,'remote-browser');image.tabIndex=0;image.alt='VNC 远程桌面';
 const desktop=node('div',undefined,'vnc-desktop'),toolbar=node('div',undefined,'vnc-toolbar');
 const fullscreen=button('全屏桌面',async()=>{if(document.fullscreenElement===desktop)await document.exitFullscreen();else await desktop.requestFullscreen();},'secondary');
 toolbar.append(fullscreen,node('span','点击桌面后使用鼠标和键盘；Esc 退出全屏。','muted'));desktop.append(toolbar,image);root.append(status,desktop);
 const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+result.websocket);
 let width=1,height=1,buttons=0,ended=false;const held=new Map();
 const send=m=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(m));};
 ws.onopen=()=>send({ticket:result.ticket});
 ws.onmessage=event=>{const m=JSON.parse(event.data);if(m.type==='ready'){width=m.width||width;height=m.height||height;image.focus();}if(m.type==='frame'){width=m.width;height=m.height;image.src='data:image/jpeg;base64,'+m.data;}if(m.type==='closed')ended=true;if(m.message)status.textContent=m.message;};
 ws.onclose=()=>{if(!ended)status.textContent='VNC 已断开，请检查目标服务与网络后重新连接。';};
 ws.onerror=()=>{status.textContent='VNC 网页连接失败，请检查堡垒机连接状态。';ended=true;};
 const point=event=>{const rect=image.getBoundingClientRect();return {type:'pointer',x:Math.max(0,Math.min(width-1,Math.floor((event.clientX-rect.left)*width/rect.width))),y:Math.max(0,Math.min(height-1,Math.floor((event.clientY-rect.top)*height/rect.height))),buttons};};
 image.oncontextmenu=event=>event.preventDefault();
 image.onpointerdown=event=>{event.preventDefault();image.focus();image.setPointerCapture(event.pointerId);buttons|=[1,2,4][event.button]||0;send(point(event));};
 image.onpointerup=event=>{buttons&=~([1,2,4][event.button]||0);send(point(event));};
 image.onpointermove=event=>send(point(event));
 image.onwheel=event=>{event.preventDefault();const m=point(event);send({...m,buttons:buttons|(event.deltaY<0?8:16)});send(m);};
 const keys={Enter:0xff0d,Tab:0xff09,Escape:0xff1b,Backspace:0xff08,Delete:0xffff,ArrowLeft:0xff51,ArrowUp:0xff52,ArrowRight:0xff53,ArrowDown:0xff54,Home:0xff50,End:0xff57,PageUp:0xff55,PageDown:0xff56,Shift:0xffe1,Control:0xffe3,Alt:0xffe9,Meta:0xffeb,CapsLock:0xffe5};
 const keyCode=event=>{if(keys[event.key])return keys[event.key];if(/^F([1-9]|1[0-2])$/.test(event.key))return 0xffbd+Number(event.key.slice(1));if([...event.key].length===1){const c=event.key.codePointAt(0);return c<256?c:0x1000000+c;}return null;};
 image.onkeydown=event=>{const code=event.code||event.key,key=held.get(code)??keyCode(event);if(key===null)return;event.preventDefault();held.set(code,key);send({type:'key',key,down:true});};
 image.onkeyup=event=>{const code=event.code||event.key,key=held.get(code)??keyCode(event);if(key===null)return;event.preventDefault();held.delete(code);send({type:'key',key,down:false});};
 const release=()=>{for(const key of held.values())send({type:'key',key,down:false});held.clear();buttons=0;send({type:'pointer',x:0,y:0,buttons:0});};
 image.onblur=release;
 image.onpointercancel=release;
 return {close:()=>{release();ws.close();if(document.fullscreenElement===desktop)document.exitFullscreen().catch(()=>{});desktop.remove();status.remove();}};
}

function attachVncSheet(root,sshAsset){
 const panel=node('section'),status=node('p','选择已授权的 VNC 资源账号。推荐单独配置同一主机的 VNC 资产和端口。','muted');panel.id='vnc-sheet';panel.hidden=true;panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby','vnc-tab');panel.append(status);root.append(panel);
 let loaded=false,disposed=false,view=null;
 const open=async()=>{
  if(loaded||disposed)return;loaded=true;
  try{
   const state=await api('/protocol-status');
   if(!state.vnc_native)throw Error('VNC 页签需要本机直连模式，请配置 VNC_BACKEND=native 后重启。');
   const assets=(await api('/assets')).filter(a=>a.protocol==='vnc'&&a.enabled!==false).sort((a,b)=>(b.host===sshAsset.host)-(a.host===sshAsset.host));
   if(disposed)return;
   const resource=node('select');resource.setAttribute('aria-label','VNC 资源');
   for(const asset of assets){const option=node('option',asset.name+' / '+asset.host+':'+asset.port);option.value=asset.id;resource.append(option);}
   const account=node('select');account.setAttribute('aria-label','VNC 系统账号');const controls=node('div');
   const loadAccounts=async()=>{const selected=resource.value;account.replaceChildren();const rows=await api('/assets/'+selected+'/accounts');if(disposed||selected!==resource.value)return;for(const row of rows.filter(a=>a.enabled)){const option=node('option',row.username);option.value=row.id;account.append(option);}};
   if(!assets.length){status.textContent='暂无可用 VNC 资源。请新增 VNC 资产、配置目标端口和密码，并授予该账号访问权限。';return;}
   resource.onchange=()=>loadAccounts().catch(error=>notify(error.message));
   actions(controls,resource,account,button('连接 VNC',async()=>{
    if(!account.value)throw Error('请选择已授权的 VNC 系统账号');
    const result=await api('/sessions','POST',{asset_id:resource.value,account_id:account.value});
    if(disposed){await api('/sessions/'+result.id+'/terminate','POST',{}).catch(()=>{});return;}
    view?.close();view=nativeVncView(panel,result);controls.hidden=true;
   }));panel.append(controls);await loadAccounts();
  }catch(error){loaded=false;status.textContent=error.message;}
 };
 return {panel,open,close:()=>{disposed=true;view?.close();}};
}
