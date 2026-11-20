// ============================================================
// 文件名称：sftp.js
// 生成日期：2026-10-26
// 修改日期：2026-11-20
// 版本信息：v0.261115
// 作    者：JUN
// 备    注：本程序由AI辅助完成。
//           文件功能：实现 sftp 模块相关功能。
//           文件用途：供堡垒机的 leizhang/static/sftp.js 模块使用。
//           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
// ============================================================
'use strict';
function attachSftpSheets(root,terminalBox,asset,accountId){
 const tabs=node('div',undefined,'connection-tabs'),files=node('section'),status=node('p','切换到此页签后连接 SFTP。','muted');
 tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label','SSH / SFTP');
 files.hidden=true;files.append(status);terminalBox.before(tabs);root.append(files);
 terminalBox.setAttribute('role','tabpanel');terminalBox.id='ssh-sheet';files.setAttribute('role','tabpanel');files.id='sftp-sheet';
 let ws=null,disposed=false,connecting=false,busy=false,upload=null,download=null,currentPath='.';
 const path=node('input');path.value='.';path.setAttribute('aria-label','远程目录');
 const listing=node('div'),file=node('input');file.type='file';file.setAttribute('aria-label','上传文件');
 const send=message=>{if(ws?.readyState!==WebSocket.OPEN)throw Error('SFTP 尚未连接');ws.send(JSON.stringify(message));};
 const refresh=()=>send({type:'list',path:currentPath});
 const join=name=>(currentPath==='/'?'':currentPath)+'/'+name;
 actions(files,path,button('打开目录',()=>{currentPath=path.value;refresh();}),button('上级目录',()=>{currentPath=join('..');refresh();},'secondary'));
 const directory=node('input');directory.setAttribute('aria-label','新目录名称');directory.placeholder='新目录名称';
 const validName=name=>{if(!name||name==='.'||name==='..'||/[\/\\\x00]/.test(name))throw Error('请输入单个文件或目录名称');return name;};
 actions(files,directory,button('新建目录',()=>send({type:'mkdir',path:join(validName(directory.value))}),'secondary'));
 actions(files,file,button('上传文件',async()=>{
  if(busy)throw Error('请等待当前传输完成');const selected=file.files[0];if(!selected)throw Error('请选择文件');
  if(selected.size>20*1024*1024)throw Error('单文件上限 20 MiB');
  const destination=join(validName(selected.name));send({type:'upload_start',path:destination});
  upload={file:selected,offset:0,path:destination};busy=true;status.textContent='正在上传；同名文件不会被覆盖。';
 }));files.append(listing);
 const fail=message=>{busy=false;upload=null;download=null;status.textContent=message;};
 const connectFiles=async()=>{
  if(ws||disposed||connecting)return;
  connecting=true;
  try{
  status.textContent='正在连接 SFTP…';
  const result=await api('/sessions','POST',{asset_id:asset.id,account_id:accountId});
  if(disposed){await api('/sessions/'+result.id+'/terminate','POST',{}).catch(()=>{});return;}
  ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/sftp/'+result.id);
  ws.onopen=()=>ws.send(JSON.stringify({ticket:result.ticket}));
  ws.onclose=()=>fail('SFTP 已断开。关闭弹窗后重新连接；未完成上传可能留下不完整文件。');
  ws.onmessage=async event=>{
   try{
    const m=JSON.parse(event.data);
    if(m.type==='ready'){currentPath=m.path;refresh();}
    if(m.type==='list'){
     currentPath=m.path;path.value=m.path;status.textContent='已连接 · 单文件上限 20 MiB · 上传不覆盖同名文件';
     listing.replaceChildren(table(m.entries,[['name','名称'],['directory','目录'],['size','字节']],row=>[button(row.directory?'打开':'下载',()=>{
      if(busy)throw Error('请等待当前传输完成');
      if(row.directory){currentPath=join(row.name);refresh();}else{send({type:'download',path:join(row.name)});busy=true;}
     },'secondary')]));
    }
    if(m.type==='upload_ack'&&upload){
     if(upload.offset<upload.file.size){
      const task=upload,bytes=new Uint8Array(await task.file.slice(task.offset,task.offset+12000).arrayBuffer());
      if(disposed||upload!==task)return;
      task.offset+=bytes.length;
      send({type:'upload_chunk',path:task.path,data:btoa(String.fromCharCode(...bytes))});
     }else send({type:'upload_end',path:upload.path});
    }
    if(m.type==='done'){busy=false;upload=null;status.textContent=m.message;refresh();}
    if(m.type==='download_start')download={name:m.name,chunks:[]};
    if(m.type==='download_chunk'&&download)download.chunks.push(Uint8Array.from(atob(m.data),c=>c.charCodeAt(0)));
    if(m.type==='download_end'&&download){
     const url=URL.createObjectURL(new Blob(download.chunks)),link=node('a');link.href=url;link.download=download.name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);download=null;busy=false;status.textContent='下载完成';
    }
    if(m.type==='error'||m.type==='closed')fail(m.message);
   }catch(error){fail(error.message);}
  };
  }finally{connecting=false;}
 };
 const vnc=attachVncSheet(root,asset),buttons=[];
 for(const [index,label]of ['SSH 终端','SFTP 文件','VNC'].entries()){
  const tab=button(label,async()=>{
   terminalBox.hidden=index!==0;files.hidden=index!==1;vnc.panel.hidden=index!==2;
   buttons.forEach((b,i)=>{b.setAttribute('aria-selected',String(i===index));b.classList.toggle('active',i===index);});
   if(index===1)await connectFiles();else if(index===2)await vnc.open();else terminal?.focus();
  },'secondary');
  tab.setAttribute('role','tab');tab.setAttribute('aria-selected',String(index===0));tab.setAttribute('aria-controls',['ssh-sheet','sftp-sheet','vnc-sheet'][index]);tab.id=['ssh-tab','sftp-tab','vnc-tab'][index];buttons.push(tab);tabs.append(tab);
 }
 terminalBox.setAttribute('aria-labelledby','ssh-tab');files.setAttribute('aria-labelledby','sftp-tab');
 window.sftpCleanup=()=>{disposed=true;ws?.close();vnc.close();upload=null;download=null;};
}
