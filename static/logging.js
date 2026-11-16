'use strict';
async function renderLogForwarding(root,request,path){
 const status=await request(path),config=status.config;
 root.replaceChildren();root.classList.add('log-forwarding');
 const add=(tag,text,parent=root)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=text;parent.append(el);return el;};
 add('h2','日志转发');add('p','转发操作及安全审计元数据，失败自动重试；首次保存从新日志开始。').className='log-description';
 const form=add('form'),checkLabel=add('label',undefined,form);checkLabel.className='check';
 const enabled=add('input',undefined,checkLabel);enabled.type='checkbox';enabled.checked=config.enabled;enabled.id='log-enabled';checkLabel.append(document.createTextNode('启用日志转发'));
 const fields=add('fieldset',undefined,form);fields.className='log-fields';const controls={};
 const definitions=[['host','接收服务器 IP','text'],['port','端口','number'],['protocol','传输协议',[['udp','UDP'],['tcp','TCP'],['tls','TLS']]],['format','数据格式',[['json','JSON'],['syslog','Syslog RFC 5424'],['custom','自定义格式']]],['facility','Syslog Facility（0–23）','number'],['template','自定义单行模板','text']];
 for(const [key,title,type] of definitions){
  const label=add('label',title,fields),input=add(Array.isArray(type)?'select':'input',undefined,label);label.className='log-field-'+key;input.id='log-'+key;
  if(Array.isArray(type))for(const [value,name] of type){const option=add('option',name,input);option.value=value;}
  else input.type=type;
  input.value=config[key];controls[key]=input;
  if(key==='port'){input.min=1;input.max=65535;input.required=true;}
  if(key==='facility'){input.min=0;input.max=23;input.required=true;}
  if(key==='template')input.maxLength=8192;
 }
 const help=add('small','模板字段：{id} {time} {source} {action} {actor} {target} {ip} {detail} {hostname} {platform_name}。{{ 和 }} 表示花括号。',form);help.className='log-template-help';
 const actions=add('div',undefined,form);actions.className='toolbar actions';const save=add('button','保存配置',actions);save.type='submit';save.id='log-save';
 const test=add('button','测试发送',actions);test.type='button';test.id='log-test';const reload=add('button','刷新状态',actions);reload.type='button';reload.id='log-refresh';
 const result=add('p');result.id='log-result';result.setAttribute('role','status');const state=add('p');state.id='log-status';
 function show(value){const s=value.state;state.textContent=`已发送 ${s.sent||0} 条 · 最近发送 ${s.last_sent_at||'暂无'} · ${s.last_error||'无发送错误'} · 来源 ${value.sources.join('、')}`;}
 function sync(){fields.disabled=!enabled.checked;test.disabled=!enabled.checked;controls.template.parentElement.hidden=controls.format.value!=='custom';help.hidden=controls.format.value!=='custom';controls.facility.parentElement.hidden=controls.format.value!=='syslog';}
 enabled.addEventListener('change',sync);controls.format.addEventListener('change',sync);sync();show(status);
 function value(){return {enabled:enabled.checked,...Object.fromEntries(Object.entries(controls).map(([k,c])=>[k,c.type==='number'?Number(c.value):c.value.trim()]))};}
 let busy=false;
 async function action(operation){if(busy)return;busy=true;save.disabled=test.disabled=reload.disabled=true;try{await operation();}catch(e){result.textContent=e.message;}finally{busy=false;save.disabled=reload.disabled=false;sync();}}
 form.addEventListener('submit',e=>{e.preventDefault();action(async()=>{show(await request(path,'PUT',value()));result.textContent='日志转发配置已保存并生效。';});});
 test.addEventListener('click',()=>action(async()=>{result.textContent=(await request(path+'/test','POST',value())).detail;}));
 reload.addEventListener('click',()=>action(async()=>{show(await request(path));result.textContent='状态已刷新。';}));
}
