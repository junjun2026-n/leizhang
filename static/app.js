'use strict';
let me=null, current='overview', socket=null, terminal=null, replayTimers=[],connectionGeneration=0;
const $=id=>document.getElementById(id);
const labels={overview:'总览',assets:'资产管理',accounts:'系统账号',users:'用户管理',grants:'资产授权',approvals:'访问审批',sessions:'会话与录像',protocolAudit:'SQL / 协议审计',audit:'操作审计',password:'修改密码'};
const roleNames={admin:'管理员',operator:'运维人员',auditor:'审计员'};
const menuPermissions={overview:['overview.view'],assets:['assets.view'],accounts:['accounts.manage'],users:['users.view'],roles:['roles.view'],permissions:['permissions.manage'],grants:['grants.view'],approvals:['approvals.view'],sessions:['sessions.view_all','recordings.view'],audit:['audit.view'],commandAudit:['commands.audit'],protocolAudit:['protocols.audit'],settings:['settings.appearance','settings.database','settings.logging']};
function hasPermission(code){
 if(Array.isArray(me?.permissions))return me.permissions.includes(code);
 if(me?.role==='admin')return true;
 const common=['overview.view','assets.view','sessions.view','approvals.view'];
 const extra=me?.role==='auditor'?['sessions.view_all','recordings.view','audit.view','commands.audit','protocols.audit']:['sessions.connect','sessions.terminate','approvals.request'];
 return !!me&&[...common,...extra].includes(code);
}
function menuAllowed(key){return key==='password'||(menuPermissions[key]||[]).some(hasPermission);}
const navigationGroups=[
 {id:'resources',label:'资源管理',pages:['assets','accounts','grants'],expanded:true},
 {id:'users',label:'用户与权限',pages:['users','roles','permissions'],expanded:true},
 {id:'audit',label:'审计',pages:['sessions','protocolAudit','audit','commandAudit'],expanded:true}
];
function setMenuExpanded(group,expanded){
 group.expanded=expanded;
 const toggle=$(group.id+'-menu-toggle'),items=$(group.id+'-menu-items');
 if(toggle)toggle.setAttribute('aria-expanded',String(expanded));
 if(items)items.hidden=!expanded;
}
function renderNavigation(){
 const nav=$('nav');nav.replaceChildren();
 const addPage=(parent,key)=>{const b=button(labels[key],()=>show(key));b.dataset.page=key;parent.append(b);};
 for(const key of Object.keys(labels)){
  const menuGroup=navigationGroups.find(group=>group.pages[0]===key);
  if(menuGroup){
   const visible=menuGroup.pages.filter(menuAllowed);
   if(visible.length){
    const group=node('div',undefined,'nav-group'),items=node('div',undefined,'nav-submenu');items.id=menuGroup.id+'-menu-items';
    const toggle=button(menuGroup.label,()=>setMenuExpanded(menuGroup,!menuGroup.expanded),'nav-group-toggle');toggle.id=menuGroup.id+'-menu-toggle';toggle.setAttribute('aria-controls',items.id);
    visible.forEach(page=>addPage(items,page));group.append(toggle,items);nav.append(group);setMenuExpanded(menuGroup,menuGroup.expanded);
   }
  }
  if(navigationGroups.some(group=>group.pages.includes(key))||!menuAllowed(key))continue;
  addPage(nav,key);
 }
}
function node(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function eyeIcon(visible){const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');for(const [key,value]of Object.entries({viewBox:'0 0 24 24',fill:'none',stroke:'currentColor','stroke-width':'1.8','stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true',focusable:'false'}))svg.setAttribute(key,value);const outline=document.createElementNS(ns,'path');outline.setAttribute('d','M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z');const pupil=document.createElementNS(ns,'circle');pupil.setAttribute('cx','12');pupil.setAttribute('cy','12');pupil.setAttribute('r','3');svg.append(outline,pupil);if(visible){const slash=document.createElementNS(ns,'path');slash.setAttribute('d','M3 3l18 18');svg.append(slash);}return svg;}
function notify(text){$('notice').textContent=text;if($('modal')?.open){let notice=$('modal-notice');if(!notice){notice=node('div',undefined,'modal-notice');notice.id='modal-notice';notice.setAttribute('role','alert');$('modal-content').prepend(notice);}notice.textContent=text;}}
async function api(path,method='GET',body){const r=await fetch('/api'+path,{method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});let data;try{data=await r.json();}catch{throw Error('服务暂不可用');}if(!r.ok){if(r.status===401&&me){me=null;loginView();}throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));}return data;}
function button(text,fn,cls){const b=node('button',text,cls);b.type='button';const required={
 '新增用户':'users.manage','角色 / 启停':'users.manage','命令黑 / 白名单':'users.policy','开启 MFA':'users.mfa','关闭 MFA':'users.mfa',
 '新增角色':'roles.manage','分配平台权限':'permissions.manage','新增资产':'assets.manage','系统账号管理':'accounts.manage',
 '授权':'grants.manage','管理授权':'grants.manage','管理此资源授权':'grants.manage','授权用户':'grants.view',
 '修改有效期':'grants.manage','撤销':'grants.manage','批量续期':'grants.manage','批量撤销':'grants.manage',
 '全选筛选结果':'grants.manage','清空勾选':'grants.manage'}[text]||(current==='roles'&&['编辑','删除'].includes(text)?'roles.manage':null);
 if(required&&!hasPermission(required))b.hidden=true;
 b.onclick=async()=>{b.disabled=true;try{await fn();}catch(e){notify(e.message);}finally{b.disabled=false;}};return b;}
function actions(parent,...items){const row=node('div',undefined,'actions');items.forEach(i=>row.append(i));parent.append(row);return row;}
function card(title){const c=node('div',undefined,'card');if(title)c.append(node('h2',title));return c;}
function table(rows,columns,ops){const wrap=node('div',undefined,'table-wrap'),t=node('table'),head=node('tr');for(const [,name]of columns)head.append(node('th',name));if(ops)head.append(node('th','操作'));t.append(head);for(const row of rows){const tr=node('tr');for(const [key,,render]of columns){if(render){const td=node('td');td.append(render(row));tr.append(td);continue;}let value=row[key];if(typeof value==='boolean')value=value?'是':'否';tr.append(node('td',value??'—'));}if(ops){const td=node('td');for(const b of ops(row))td.append(b);tr.append(td);}t.append(tr);}if(!rows.length){const tr=node('tr'),td=node('td','暂无记录');td.colSpan=columns.length+(ops?1:0);tr.append(td);t.append(tr);}wrap.append(t);return wrap;}
function form(parent,fields,submit,label='保存'){
 const f=node('form'),inputs={};
 for(const item of fields){
  const [name,title,type='text',value='',options]=item;
  const l=node('label',title);let input;
  if(type==='select'){input=node('select');for(const [v,text]of options){const o=node('option',text);o.value=v;input.append(o);}}
  else{input=node(type==='textarea'?'textarea':'input');if(type!=='textarea')input.type=type;}
  if(type==='checkbox')input.checked=!!value;else input.value=value;
  input.name=name;input.setAttribute('aria-label',title);
  if(type==='password'){
   input.autocomplete=(name==='old_password'||(name==='password'&&label==='登录'))?'current-password':'new-password';
   const control=node('div',undefined,'password-field');
   const toggle=node('button',undefined,'password-toggle secondary');toggle.type='button';toggle.append(eyeIcon(false));
   toggle.setAttribute('aria-label','显示'+title);toggle.title='显示'+title;toggle.setAttribute('aria-pressed','false');
   toggle.onclick=()=>{
    const visible=input.type==='password';input.type=visible?'text':'password';
    toggle.replaceChildren(eyeIcon(visible));toggle.setAttribute('aria-label',(visible?'隐藏':'显示')+title);toggle.title=(visible?'隐藏':'显示')+title;
    toggle.setAttribute('aria-pressed',String(visible));
   };
   control.append(input,toggle);l.append(control);
  }else l.append(input);
  f.append(l);inputs[name]=input;
 }
 const b=node('button',label);b.type='submit';actions(f,b);
 f.onsubmit=async e=>{e.preventDefault();b.disabled=true;try{const data={};for(const [key,input]of Object.entries(inputs))data[key]=input.type==='checkbox'?input.checked:input.type==='number'?Number(input.value):input.value;await submit(data);}catch(err){notify(err.message);}finally{b.disabled=false;}};
 parent.append(f);return inputs;
}
function openModal(title){closeTerminal();$('modal-title').textContent=title;$('modal-content').replaceChildren();if(!$('modal').open)$('modal').showModal();$('modal-body').scrollTop=0;return $('modal-content');}
function confirmAction(title,message,submit,after,label='确认'){
 const c=openModal(title);c.append(node('p',message));
 actions(c,button(label,async()=>{await submit();$('modal').close();if(after)await after();},'danger'));
}
function closeTerminal(){connectionGeneration++;if(window.sftpCleanup){window.sftpCleanup();window.sftpCleanup=null;}if(window.protocolCleanup){window.protocolCleanup();window.protocolCleanup=null;}if(socket){socket.close();socket=null;}if(terminal){terminal.dispose();terminal=null;}for(const t of replayTimers)clearTimeout(t);replayTimers=[];}
$('modal-close-top').onclick=()=>$('modal').close();$('modal').addEventListener('close',closeTerminal);
function loginView(){current='overview';$('title').textContent='登录安全运维工作台';$('nav').replaceChildren();$('identity').replaceChildren();const c=card('登录');c.classList.add('login');c.append(node('p','首次使用仅需账号和密码；管理员启用 MFA 后才需要动态验证码。','muted'));const inputs=form(c,[['username','用户名'],['password','密码','password'],['code','MFA 动态验证码（仅已启用账号填写）']],async data=>{await api('/auth/login','POST',data);await boot();},'登录');inputs.code.parentElement.hidden=true;const mfaToggle=button('已启用 MFA？填写验证码',()=>{const expanded=inputs.code.parentElement.hidden;inputs.code.parentElement.hidden=!expanded;mfaToggle.setAttribute('aria-expanded',String(expanded));if(expanded)inputs.code.focus();},'secondary login-mfa');mfaToggle.setAttribute('aria-expanded','false');inputs.code.id='login-mfa-code';mfaToggle.setAttribute('aria-controls',inputs.code.id);const row=c.querySelector('form > .actions');row.classList.add('login-actions');row.append(mfaToggle);$('content').replaceChildren(c);}
async function boot(){try{me=await api('/auth/me');}catch{loginView();return;}$('identity').replaceChildren(node('span',me.username+' · '+(me.role_name||roleNames[me.role]||me.role)));$('identity').append(button('退出',async()=>{await api('/auth/logout','POST',{});me=null;loginView();},'secondary'));renderNavigation();if(!menuAllowed(current))current=Object.keys(labels).find(menuAllowed)||'password';await Promise.all([show(current),refreshApprovalReminders()]);}
async function show(key){if(!menuAllowed(key)){notify('没有该功能的平台权限');return;}current=key;notify('');$('title').textContent=labels[key];document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===key));for(const group of navigationGroups){const active=group.pages.includes(key);if(active)setMenuExpanded(group,true);$(group.id+'-menu-toggle')?.classList.toggle('active',active);}const root=$('content');root.replaceChildren();try{await pages[key](root);}catch(e){notify(e.message);}}
const pages={};
pages.protocolAudit=root=>protocolAuditView(root);
pages.overview=async root=>{const data=await api('/statistics'),grid=node('div',undefined,'stats');for(const [key,label]of [['assets','可见资产'],['sessions','累计会话'],['active','在线会话'],['failures','失败会话']]){const c=card();c.append(node('span',label),node('strong',data[key]));grid.append(c);}root.append(grid);const c=card('运维流程');c.append(node('p','管理员录入资产并核验 SSH 主机公钥 → 授予限时访问权限 → 运维人员申请审批 → 打开网页终端 → 审计员查看录像。','muted'));c.append(node('p','支持 SSH、TELNET、RDP、VNC、HTTP 远程浏览，以及 PostgreSQL、MySQL/MariaDB 网页 SQL 控制台。RDP 需要 Guacamole 网关; VNC 支持网页直连 Linux 桌面；SQL 审计覆盖本控制台执行的语句。','muted'));actions(c,button('刷新统计',()=>show('overview'),'secondary'));root.append(c);};
pages.assets=async root=>{
 const rows=await api('/assets');if(hasPermission('assets.manage')||hasPermission('accounts.manage'))actions(root,button('新增资产',()=>assetEdit()),button('系统账号管理',()=>show('accounts'),'secondary'));
 const columns=[['name','资产名称'],['protocol','协议'],['host','地址'],['port','端口'],['accounts','系统账号',row=>node('span',(row.accounts||[]).map(a=>a.username+(a.enabled?'':'（停用）')).join('、')||'暂无账号')],['tags','标签'],['enabled','启用'],['approval_required','需审批']];
 columns.push(hasPermission('assets.view_all')?['granted_user_count','有效授权用户数']:['authorization_expires_at','我的账号授权到期',row=>{const box=node('div');for(const account of row.accounts||[])box.append(node('div',account.username+'：'+new Date(account.expires_at).toLocaleString()));return box;}]);
 root.append(table(rows,columns,row=>{
  const ops=[];if(hasPermission('sessions.connect')){ops.push(button('连接',()=>connect(row)));if(row.protocol==='ssh')ops.push(button('SSH 客户端',()=>nativeSsh(row),'secondary'));}if(hasPermission('approvals.request')&&hasPermission('sessions.connect'))ops.push(button('申请访问',()=>approvalForm(row),'secondary'));
  if(hasPermission('assets.manage'))ops.push(button('修改',()=>assetEdit(row),'secondary'));if(hasPermission('accounts.manage'))ops.push(button('系统账号',()=>manageAccounts(row),'secondary'));if(hasPermission('grants.view'))ops.push(button('授权用户',()=>resourceGrants(row),'secondary'));return ops;
 }));
};
async function resourceGrants(asset){
 const [users,grants]=await Promise.all([api('/users'),api('/grants')]);
 const c=openModal('授权用户 · '+asset.name);c.append(node('p',asset.host+':'+asset.port));
 const rows=grants.filter(g=>g.asset_id===asset.id).map(g=>{const user=users.find(u=>u.id===g.user_id),account=asset.accounts?.find(a=>a.id===(g.account_id||asset.id));return {...g,username:user?.username,system_username:account?.username||'账号已删除',status:new Date(g.expires_at)<=new Date()?'已过期':(!user?.enabled||(user?.can_connect===false||(user?.can_connect===undefined&&user?.role==='auditor'))?'用户不可用':(!asset.enabled||!account?.enabled?'资源或账号停用':'有效')),expires_at:new Date(g.expires_at).toLocaleString()};});
 c.append(table(rows,[['username','平台用户'],['system_username','系统账号'],['status','授权状态'],['expires_at','到期时间']]));
 actions(c,button('管理此资源授权',async()=>{$('modal').close();grantFilters={asset_id:asset.id,user_id:'',status:'all',q:''};await show('grants');}));
}
async function manageAccounts(asset){
 const accounts=await api('/assets/'+asset.id+'/accounts'),c=openModal('系统账号 · '+asset.name);
 c.append(node('p','同一资源可配置多个系统账号，密码或私钥分别加密保存。授权按具体系统账号分配；新增账号不会自动继承原有授权。','muted'));
 actions(c,button('新增系统账号',()=>accountEdit(asset)));
 c.append(table(accounts,[['username','系统账号'],['auth_type','认证方式'],['enabled','启用']],account=>[
  button('修改',()=>accountEdit(asset,account),'secondary'),
  button(account.enabled?'停用':'启用',async()=>{await api('/assets/'+asset.id+'/accounts/'+account.id,'PUT',{username:account.username,auth_type:account.auth_type,credential:'',enabled:!account.enabled});await show('assets');await manageAccounts(asset);},'secondary'),
  button('授权',async()=>{$('modal').close();grantFilters={asset_id:asset.id,user_id:'',status:'all',q:''};await show('grants');const accountSelect=document.querySelector('#content form select[name=account_id]');accountSelect.value=account.id;},'secondary'),
  button('删除',()=>confirmAction('删除系统账号','删除系统账号 '+account.username+'？将撤销此账号全部授权并终止对应会话，历史审计与录像保留。',()=>api('/assets/'+asset.id+'/accounts/'+account.id,'DELETE',{}),async()=>{await show('assets');await manageAccounts(asset);},'确认删除'),'danger')
 ]));
}
function accountEdit(asset,account={},onDone=null){
 const c=openModal((account.id?'修改':'新增')+'系统账号 · '+asset.name);
 c.append(node('p','修改时凭据留空保留。停用账号、更换用户名或凭据会终止该账号的现有会话。','muted'));
 const inputs=form(c,[['username','资源系统用户名','text',account.username||''],['auth_type','认证方式','select',account.auth_type||'password',[['password','密码'],['private_key','SSH 私钥']]],['password','系统密码（加密保存）','password'],['private_key','SSH 私钥（未加口令）','textarea'],['enabled','启用','checkbox',account.enabled??true]],async data=>{const body={username:data.username,auth_type:data.auth_type,credential:data.auth_type==='password'?data.password:data.private_key,enabled:data.enabled};await api('/assets/'+asset.id+'/accounts'+(account.id?'/'+account.id:''),account.id?'PUT':'POST',body);if(onDone){$('modal').close();await onDone();}else{await show('assets');await manageAccounts(asset);}},'保存账号');
 inputs.enabled.parentElement.classList.add('account-enabled-option');
 if(asset.protocol&&asset.protocol!=='ssh'){inputs.auth_type.value='password';inputs.auth_type.disabled=true;}inputs.username.required=true;
 const update=()=>{inputs.password.parentElement.parentElement.hidden=inputs.auth_type.value!=='password';inputs.private_key.parentElement.hidden=inputs.auth_type.value!=='private_key';};inputs.auth_type.onchange=update;update();
}
let accountFilters={asset_id:'',status:'all',q:''};
async function openAccountAuthorization(asset,account){
 $('modal').close();grantFilters={asset_id:asset.id,user_id:'',status:'all',q:account.username};await show('grants');
 const select=document.querySelector('#content form select[name=account_id]');if(select)select.value=account.enabled?account.id:'';
}
pages.accounts=async root=>{
 if(!menuAllowed(current))throw Error('没有平台权限');
 const [assets,users,grants]=await Promise.all([api('/assets'),api('/users'),api('/grants')]);
 const userMap=new Map(users.map(user=>[user.id,user]));
 const rows=assets.flatMap(asset=>(asset.accounts||[]).map(account=>{
  const authorizations=grants.filter(grant=>grant.asset_id===asset.id&&(grant.account_id||asset.id)===account.id);
  const active=authorizations.filter(grant=>new Date(grant.expires_at)>new Date()&&userMap.get(grant.user_id)?.enabled&&(userMap.get(grant.user_id)?.can_connect??userMap.get(grant.user_id)?.role==='operator'));
  return {asset,account,asset_id:asset.id,resource:asset.name,host:asset.host,username:account.username,auth_label:account.auth_type==='password'?'密码':'SSH 私钥',status:!asset.enabled?'资源停用':(account.enabled?'启用':'账号停用'),authorized_users:active.map(grant=>userMap.get(grant.user_id).username).join('、')||'暂无',granted_count:new Set(active.map(grant=>grant.user_id)).size,authorizations};
 }));
 const controls=card('系统账号管理');controls.append(node('p','集中管理各资源下的系统账号。新增账号后需单独授权；此处录入的是目标服务器上已存在的账号。','muted'));
 const refresh=()=>show('accounts');
 const create=()=>{
  if(!assets.length){notify('请先到“资产管理”新增资源，再添加系统账号');return;}
  const c=openModal('新增系统账号 · 选择资源');
  const inputs=form(c,[['asset_id','所属资源','select',accountFilters.asset_id||assets[0].id,assets.map(asset=>[asset.id,asset.name+' / '+asset.host])]],async data=>{const asset=assets.find(asset=>asset.id===data.asset_id);if(!asset)throw Error('请选择所属资源');accountEdit(asset,{},refresh);},'下一步');
  inputs.asset_id.required=true;
 };
 actions(controls,button('新增系统账号',create),button('刷新',refresh,'secondary'));
 const list=node('div'),summary=node('p',undefined,'muted');
 const accountUsers=row=>{
  const c=openModal('授权用户 · '+row.resource+' / '+row.username);
  const mapped=row.authorizations.map(grant=>{const user=userMap.get(grant.user_id);return {username:user?.username||grant.user_id,status:new Date(grant.expires_at)<=new Date()?'已过期':(!user?.enabled||(user.can_connect===false||(user.can_connect===undefined&&user.role==='auditor'))||row.status!=='启用'?'不可用':'有效'),expires_at:new Date(grant.expires_at).toLocaleString()};});
  c.append(table(mapped,[['username','平台用户'],['status','状态'],['expires_at','到期时间']]));actions(c,button('管理授权',()=>openAccountAuthorization(row.asset,row.account)));
 };
 const render=()=>{
  const query=accountFilters.q.trim().toLowerCase();
  const visible=rows.filter(row=>(!accountFilters.asset_id||row.asset_id===accountFilters.asset_id)&&(accountFilters.status==='all'||row.status===accountFilters.status)&&(!query||[row.resource,row.host,row.username,row.authorized_users].some(value=>value.toLowerCase().includes(query))));
  summary.textContent='共 '+rows.length+' 个系统账号 · 启用 '+rows.filter(row=>row.status==='启用').length+' · 不可用 '+rows.filter(row=>row.status!=='启用').length+' · 当前显示 '+visible.length+' 个';
  list.replaceChildren(table(visible,[['resource','所属资源'],['host','资源地址'],['username','系统账号'],['auth_label','认证方式'],['status','状态'],['granted_count','有效授权人数'],['authorized_users','已授权平台用户']],row=>[
   button('修改',()=>accountEdit(row.asset,row.account,refresh),'secondary'),
   button(row.account.enabled?'停用':'启用',async()=>{await api('/assets/'+row.asset_id+'/accounts/'+row.account.id,'PUT',{username:row.username,auth_type:row.account.auth_type,credential:'',enabled:!row.account.enabled});await refresh();},'secondary'),
   button('授权',()=>{if(!row.account.enabled)throw Error('请先启用此系统账号');return openAccountAuthorization(row.asset,row.account);},'secondary'),
   button('授权用户',()=>accountUsers(row),'secondary'),
   button('删除',()=>confirmAction('删除系统账号','删除 '+row.resource+' / '+row.username+'？此账号的授权及活动会话将被撤销，历史录像和审计保留。',()=>api('/assets/'+row.asset_id+'/accounts/'+row.account.id,'DELETE',{}),refresh,'确认删除'),'danger')
  ]));
  if(!rows.length)list.prepend(node('p',assets.length?'暂无系统账号，点击“新增系统账号”添加。':'暂无资源，请先进入“资产管理”新增资源。','muted'));
 };
 form(controls,[['asset_id','所属资源','select',accountFilters.asset_id,[['','全部资源'],...assets.map(asset=>[asset.id,asset.name])]],['status','账号状态','select',accountFilters.status,[['all','全部状态'],['启用','启用'],['账号停用','账号停用'],['资源停用','资源停用']]],['q','搜索账号、资源、地址或授权用户','text',accountFilters.q]],async data=>{accountFilters=data;render();},'筛选');
 controls.querySelector('form > .actions').append(button('重置筛选',async()=>{accountFilters={asset_id:'',status:'all',q:''};await refresh();},'secondary'));
 controls.append(summary);root.append(controls,list);render();
};
function assetEdit(row={}){
 const c=openModal(row.id?'修改资产':'新增资产');
 c.append(node('p','默认使用系统账号和密码连接，无需填写公钥。可按需开启 SSH 主机公钥校验。修改时认证凭据留空表示保留。','muted'));
 const inputs=form(c,[['protocol','协议','select',row.protocol||'ssh',Object.entries(protocolNames)],['database_name','数据库名称','text',row.database_name||''],['domain','Windows 域（可选）','text',row.domain||''],['http_scheme','HTTP 协议','select',row.http_scheme||'http',[['http','HTTP'],['https','HTTPS']]],['http_path','HTTP 起始路径','text',row.http_path||'/'],['tls_verify','校验 TLS / 远程证书','checkbox',row.tls_verify??true],['name','名称','text',row.name||''],['host','IP / 主机名','text',row.host||''],['port','连接端口','number',row.port||22],['username','资源系统账号（与平台用户独立）','text',row.username||''],['auth_type','认证方式','select',row.auth_type||'password',[['password','密码'],['private_key','SSH 私钥']]],['credential','密码或私钥（加密存储）','textarea'],['host_key','受信任主机公钥（开启校验时必填）','textarea',row.host_key||''],['tags','标签','text',row.tags||''],['enabled','启用','checkbox',row.enabled??true],['approval_required','需要审批','checkbox',row.approval_required??true]],async data=>{await api('/assets'+(row.id?'/'+row.id:''),row.id?'PUT':'POST',data);$('modal').close();await show('assets');});
 if(row.id){for(const key of ['username','auth_type','credential'])inputs[key].parentElement.hidden=true;c.append(node('p','系统账号、密码及认证方式请通过资源列表的“系统账号”按钮管理。','muted'));}
 inputs.host_key.placeholder='ssh-ed25519 AAAA... 或其他 OpenSSH 主机公钥';
 inputs.host_key.oninvalid=()=>inputs.host_key.setCustomValidity('请填写 SSH 主机公钥，或获取并核验指纹后使用。');
 inputs.host_key.oninput=()=>inputs.host_key.setCustomValidity('');
 const help=node('div');
 help.append(node('p','也可在目标服务器控制台执行：cat /etc/ssh/ssh_host_ed25519_key.pub；核验指纹：ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256','muted'));
 const result=node('div');
 actions(help,button('获取主机公钥',async()=>{
  const host=inputs.host.value.trim(),port=Number(inputs.port.value);
  if(!host)throw Error('请先填写资产 IP / 主机名和 SSH 端口');
  const data=await api('/assets/host-key/probe','POST',{host,port});
  result.replaceChildren(node('p',data.message,'muted'),node('pre','SHA256 指纹：'+data.fingerprint,'recording'),node('pre',data.host_key,'recording'));
  const confirmation=node('label','我已通过服务器控制台等可信渠道核验此 SHA256 指纹一致');
  const check=node('input');check.type='checkbox';confirmation.append(check);result.append(confirmation);
  const apply=button('使用已核验公钥',()=>{
   if(!check.checked)throw Error('请先核验并确认指纹');
   if(inputs.host.value.trim()!==host||Number(inputs.port.value)!==port)throw Error('资产地址或端口已改变，请重新获取公钥');
   inputs.host_key.value=data.host_key;inputs.host_key.setCustomValidity('');result.replaceChildren(node('p','已填入主机公钥，可继续保存资产。','muted'));
  });apply.disabled=true;check.onchange=()=>{apply.disabled=!check.checked;};actions(result,apply);
 },'secondary'));
 help.append(result);inputs.host_key.parentElement.after(help);
 const policyLabel=node('label','校验 SSH 主机公钥（可选）','tls-option'),policy=node('input');policy.type='checkbox';policy.name='verify_host_key';policy.checked=row.verify_host_key??false;policyLabel.prepend(policy);inputs.host_key.parentElement.before(policyLabel);inputs.verify_host_key=policy;
 const updatePolicy=()=>{inputs.host_key.required=policy.checked;inputs.host_key.setCustomValidity('');inputs.host_key.parentElement.hidden=!policy.checked;help.hidden=!policy.checked;};policy.onchange=updatePolicy;updatePolicy();
 const options=node('div',undefined,'asset-options');inputs.enabled.parentElement.before(options);
 for(const key of ['enabled','approval_required']){const label=inputs[key].parentElement;label.prepend(inputs[key]);options.append(label);}
 inputs.protocol.disabled=!!row.id;inputs.tls_verify.parentElement.classList.add('tls-option');
 const updateProtocol=()=>{
  const p=inputs.protocol.value,ssh=p==='ssh';
  for(const [key,visible]of Object.entries({database_name:['postgresql','mysql'].includes(p),domain:p==='rdp',http_scheme:p==='http',http_path:p==='http',tls_verify:['rdp','http','postgresql','mysql'].includes(p)}))inputs[key].parentElement.hidden=!visible;
  inputs.database_name.required=['postgresql','mysql'].includes(p);policyLabel.hidden=!ssh;
  if(!ssh){policy.checked=false;inputs.auth_type.value='password';}updatePolicy();
  [...inputs.auth_type.options].find(o=>o.value==='private_key').disabled=!ssh;
 };inputs.protocol.onchange=()=>{inputs.port.value=protocolPorts[inputs.protocol.value];updateProtocol();};updateProtocol();
 c.querySelector('form > .actions').classList.add('asset-actions');
}
pages.users=async root=>{
 const [rows,roles]=await Promise.all([api('/users'),api('/roles')]);
 const tip=card('MFA 管理');tip.append(node('p','新账号默认关闭 MFA。点击“开启 MFA”，完成身份验证器绑定并验证一次动态验证码后生效；关闭可恢复仅密码登录。','muted'));root.append(tip);
 actions(root,button('新增用户',()=>{const c=openModal('新增用户');form(c,[['username','用户名'],['password','初始密码（至少 12 位）','password'],['role_id','角色','select','operator',roles.map(r=>[r.id,r.name])]],async data=>{const result=await api('/users','POST',data);$('modal').close();await show('users');notify(result.message);});}),button('角色管理',()=>show('roles'),'secondary'));
 root.append(table(rows,[['username','用户名'],['role','角色',row=>node('span',row.role_name||roleNames[row.role]||row.role)],['command_mode','用户命令策略',row=>node('span',commandModeNames[row.command_mode]||'不限制')],['enabled','启用'],['mfa','MFA 已开启']],row=>{
  const ops=[];
  if(me.role==='admin'&&hasPermission('users.manage')&&row.role!=='admin'&&row.id!==me.id)ops.push(button('重置密码',()=>{
   const c=openModal('重置密码 · '+row.username);c.append(node('p','保存后该用户需重新登录，现有连接会话会终止；MFA 设置保持不变。','muted'));
   const fields=form(c,[['new_password','新密码（至少 12 位）','password'],['confirm_password','确认新密码','password']],async data=>{
    if(data.new_password!==data.confirm_password)throw Error('两次输入的新密码不一致');
    const result=await api('/users/'+row.id+'/password','POST',{new_password:data.new_password});fields.new_password.value='';fields.confirm_password.value='';$('modal').close();notify(result.message);
   },'确认重置');for(const field of Object.values(fields)){field.required=true;field.minLength=12;field.maxLength=256;}
  },'secondary'));
  if(row.id!==me.id)ops.push(button('角色 / 启停',()=>{const c=openModal('修改 '+row.username);const fields=form(c,[['role_id','角色','select',row.role_id,roles.map(r=>[r.id,r.name])],['enabled','启用','checkbox',row.enabled]],async data=>{await api('/users/'+row.id,'PATCH',{...data,role:roles.find(r=>r.id===data.role_id).base_role});$('modal').close();await show('users');});fields.enabled.parentElement.classList.add('account-enabled-option');},'secondary'));
  ops.push(button('命令黑 / 白名单',()=>editUserCommandPolicy(row,roles),'secondary'));
  ops.push(button(row.mfa?'关闭 MFA':'开启 MFA',async()=>{
   if(row.mfa){const c=openModal('关闭 MFA · '+row.username);c.append(node('p','确认关闭？关闭后该用户只需账号和密码即可登录。'));actions(c,button('确认关闭',async()=>{await api('/users/'+row.id+'/mfa/disable','POST',{});$('modal').close();await show('users');notify('MFA 已关闭');}));return;}
   const result=await api('/users/'+row.id+'/mfa/setup','POST',{});const c=openModal('开启 MFA · '+row.username);
   c.append(node('p','在身份验证器中添加基于时间的账号，输入下方密钥。绑定配置仅本次显示，10 分钟内完成验证。','muted'),node('pre','TOTP 密钥：'+result.secret,'recording'),node('pre',result.mfa_uri,'recording'));
   form(c,[['code','身份验证器六位动态验证码']],async data=>{const enabled=await api('/users/'+row.id+'/mfa/enable','POST',data);$('modal').close();await show('users');notify(enabled.message);},'确认开启');
  },row.mfa?'danger':'secondary'));
  return ops;
 }));
};
let grantFilters={asset_id:'',user_id:'',status:'all',q:''};
pages.grants=async root=>{
 const [users,assets,grants]=await Promise.all([api('/users'),api('/assets'),api('/grants')]);
 const c=card('资源授权 · 同一资源可授权多个平台用户');
 c.append(node('p','先选择资源和具体系统账号，再选择平台用户。每个账号独立授权、到期和撤销；资源授权不会扩大到其他系统账号。平台用户无需获取资源密码。','muted'));
 const userList=node('div',undefined,'grant-users');
 const eligibleUsers=users.filter(u=>u.enabled&&(u.can_connect??['admin','operator'].includes(u.role)));
 const selectionSummary=node('p',undefined,'muted');
 const updateUserSelection=()=>selectionSummary.textContent='可授权 '+eligibleUsers.length+' 人，已选 '+userList.querySelectorAll('input:checked').length+' 人';
 for(const user of users){const label=node('label'),check=node('input');check.type='checkbox';check.value=user.id;check.name='grant_user';check.disabled=!eligibleUsers.includes(user);check.setAttribute('aria-label','选择平台用户 '+user.username);check.onchange=updateUserSelection;const role=user.role_name||{admin:'管理员',operator:'运维用户',auditor:'审计员'}[user.role]||user.role;const reason=!user.enabled?'账号已停用':(user.can_connect===false||(user.can_connect===undefined&&user.role==='auditor'))?'未分配连接资源权限':check.disabled?'角色不可授权':'';label.append(check,node('span',user.username+'（'+role+(reason?' · '+reason:'')+'）'));if(reason)label.title=reason;userList.append(label);}
 const inputs=form(c,[['asset_id','资源（名称 / 地址）','select',grantFilters.asset_id||assets[0]?.id||'',assets.map(a=>[a.id,a.name+' / '+a.host])],['account_id','授权系统账号','select','',[]],['hours','有效小时（1～8760）','number',24]],async data=>{
  const user_ids=[...userList.querySelectorAll('input:checked')].map(input=>input.value);if(!user_ids.length)throw Error('请至少选择一个平台用户');
  if(!data.asset_id)throw Error('请先创建资源');
  if(!data.account_id)throw Error('请选择要授权的系统账号');
  const result=await api('/grants/batch','POST',{...data,user_ids});await show('grants');notify('已为 '+result.count+' 个平台用户保存资源授权，其他用户的授权不受影响');
 },'保存所选用户授权');
 inputs.hours.min=1;inputs.hours.max=8760;
 const updateAccounts=()=>{const asset=assets.find(a=>a.id===inputs.asset_id.value);inputs.account_id.replaceChildren();for(const account of (asset?.accounts||[]).filter(a=>a.enabled)){const option=node('option',account.username+'（'+(account.auth_type==='password'?'密码':'私钥')+'）');option.value=account.id;inputs.account_id.append(option);}};inputs.asset_id.onchange=updateAccounts;updateAccounts();
 const usersBox=node('div');usersBox.append(node('p','选择平台用户（可多选）'));
 actions(usersBox,button('全选',()=>{userList.querySelectorAll('input:not(:disabled)').forEach(input=>input.checked=true);updateUserSelection();},'secondary'),button('清空选择',()=>{userList.querySelectorAll('input').forEach(input=>input.checked=false);updateUserSelection();},'secondary'));
 usersBox.append(selectionSummary,userList);updateUserSelection();
 usersBox.append(node('p','仅可选择已启用且具有“连接资源”平台权限的用户。资源账号授权与平台功能权限分别生效。','muted'));
 if(!eligibleUsers.length){usersBox.append(node('p','暂无可授权用户，请到“用户管理”创建或启用运维用户后刷新列表。','muted'));actions(usersBox,button('前往用户管理',()=>show('users'),'secondary'));}
 c.querySelector('form .actions').before(usersBox);if(hasPermission('grants.manage'))root.append(c);
 const mapped=grants.map(g=>{const asset=assets.find(a=>a.id===g.asset_id),account=asset?.accounts?.find(a=>a.id===(g.account_id||asset.id)),user=users.find(u=>u.id===g.user_id),remaining=new Date(g.expires_at)-new Date();return {...g,account_id:g.account_id||g.asset_id,username:user?.username,asset:asset?.name,host:asset?.host,system_username:account?.username||'账号已删除',status:remaining<=0?'已过期':(!user?.enabled||(user?.can_connect===false||(user?.can_connect===undefined&&user?.role==='auditor'))||!asset?.enabled||!account?.enabled?'不可用':(remaining<=86400000?'即将到期':'有效'))};});
 const filters=card('查询与批量管理'),list=node('div'),summary=node('p',undefined,'muted'),selection=new Map();let filtered=[];
 const selectionStatus=node('span','已选 0 项');
 const key=g=>g.user_id+':'+g.asset_id+':'+g.account_id;
 const updateSelection=()=>selectionStatus.textContent='已选 '+selection.size+' 项（最多 100 项）';
 const rowActions=g=>!hasPermission('grants.manage')?[]:[
  button('修改有效期',()=>{const c=openModal('修改授权有效期');c.append(node('p',g.username+' → '+g.asset+'（系统账号：'+g.system_username+'）'));form(c,[['hours','从现在起有效小时（1～8760）','number',24]],async data=>{await api('/grants','POST',{...data,user_id:g.user_id,asset_id:g.asset_id,account_id:g.account_id});$('modal').close();await show('grants');});},'secondary'),
  button('撤销',()=>confirmAction('撤销资源授权','仅撤销 '+g.username+' 对此资源的授权并终止其会话？其他用户不受影响。',()=>api('/grants/'+g.user_id+'/'+g.asset_id+'/'+g.account_id,'DELETE',{}),()=>show('grants'),'确认撤销'),'danger')
 ];
 const render=()=>{
  selection.clear();updateSelection();
  filtered=mapped.filter(g=>(!grantFilters.asset_id||g.asset_id===grantFilters.asset_id)&&(!grantFilters.user_id||g.user_id===grantFilters.user_id)&&(grantFilters.status==='all'||g.status===grantFilters.status)&&(!grantFilters.q||[g.username,g.asset,g.host,g.system_username].some(value=>String(value||'').toLowerCase().includes(grantFilters.q.toLowerCase()))));
  const counts={};for(const row of mapped)counts[row.status]=(counts[row.status]||0)+1;
  summary.textContent='全部 '+mapped.length+' 项 · 有效 '+(counts['有效']||0)+' · 24 小时内到期 '+(counts['即将到期']||0)+' · 已过期 '+(counts['已过期']||0)+' · 不可用 '+(counts['不可用']||0)+'；当前筛选 '+filtered.length+' 项';
  list.replaceChildren(table(filtered,[['_select','选择',g=>{const input=node('input');input.type='checkbox';input.name='grant_selection';input.disabled=!hasPermission('grants.manage');input.setAttribute('aria-label','选择 '+g.username+' / '+g.asset);input.onchange=()=>{if(input.checked){if(selection.size>=100){input.checked=false;notify('单次最多选择 100 项授权');return;}selection.set(key(g),g);}else selection.delete(key(g));updateSelection();};return input;}],['username','平台用户'],['asset','资源'],['host','资源地址'],['system_username','资源系统账号'],['status','授权状态'],['expires_at','到期时间',g=>node('span',new Date(g.expires_at).toLocaleString())]],rowActions));
 };
 form(filters,[['q','搜索用户、资源、地址或系统账号','text',grantFilters.q],['asset_id','筛选资源','select',grantFilters.asset_id,[['','全部资源'],...assets.map(a=>[a.id,a.name])]],['user_id','筛选平台用户','select',grantFilters.user_id,[['','全部用户'],...users.map(u=>[u.id,u.username])]],['status','授权状态','select',grantFilters.status,[['all','全部状态'],['有效','有效'],['即将到期','24 小时内到期'],['已过期','已过期'],['不可用','不可用']]]],async data=>{grantFilters={...data,q:data.q.trim()};render();},'筛选');
 const selectionActions=actions(filters,button('重置筛选',async()=>{grantFilters={asset_id:'',user_id:'',status:'all',q:''};await show('grants');},'secondary'),button('刷新列表',()=>show('grants'),'secondary'));
 const filterForm=filters.querySelector('form'),filterSubmit=filterForm.querySelector('button[type=submit]');
 filterForm.id='grant-filter-form';filterSubmit.setAttribute('form',filterForm.id);
 const filterSubmitRow=filterSubmit.parentElement;selectionActions.prepend(filterSubmit);filterSubmitRow.remove();
 const targets=()=>{if(!selection.size)throw Error('请先勾选授权记录');return [...selection.values()].map(g=>({user_id:g.user_id,asset_id:g.asset_id,account_id:g.account_id}));};
 selectionActions.append(button('全选筛选结果',()=>{if(filtered.length>100)throw Error('筛选结果超过 100 项，请缩小筛选范围');filtered.forEach(g=>selection.set(key(g),g));list.querySelectorAll('input[name=grant_selection]').forEach(input=>input.checked=true);updateSelection();},'secondary'),button('清空勾选',()=>{selection.clear();list.querySelectorAll('input[name=grant_selection]').forEach(input=>input.checked=false);updateSelection();},'secondary'),selectionStatus);
 actions(filters,button('批量续期',()=>{const selected=targets(),c=openModal('批量续期');c.append(node('p','已选 '+selected.length+' 项授权。有效授权从原到期时间增加时长，已过期授权从现在开始计算。'));form(c,[['hours','增加小时（1～8760）','number',24]],async data=>{const result=await api('/grants/actions','POST',{targets:selected,action:'renew',hours:data.hours});$('modal').close();await show('grants');notify('已续期 '+result.count+' 项授权');},'确认续期');},'secondary'),button('批量撤销',()=>{const selected=targets(),c=openModal('批量撤销授权');c.append(node('p','确认撤销已选 '+selected.length+' 项授权？对应用户在所选资源上的活动会话会终止，其他授权不受影响。'));actions(c,button('确认撤销',async()=>{const result=await api('/grants/actions','POST',{targets:selected,action:'revoke'});$('modal').close();await show('grants');notify('已撤销 '+result.count+' 项授权');},'danger'));},'danger'));
 filters.append(summary);root.append(filters,list);render();
};
async function chooseSystemAccount(asset,onChoose){
 const accounts=(await api('/assets/'+asset.id+'/accounts')).filter(account=>account.enabled);
 if(!accounts.length)throw Error('暂无可用系统账号，请联系管理员配置并授权');
 if(accounts.length===1)return onChoose(accounts[0].id);
 const c=openModal('选择系统账号 · '+asset.name);c.append(node('p','仅显示当前平台用户有权使用的账号，连接使用所选账号的独立凭据。','muted'));
 form(c,[['account_id','资源系统账号','select',accounts[0].id,accounts.map(account=>[account.id,account.username+'（'+(account.auth_type==='password'?'密码':'私钥')+'）'+(account.expires_at?' · 到期 '+new Date(account.expires_at).toLocaleString():'')])]],async data=>{await onChoose(data.account_id);},'继续');
 
}
async function approvalForm(asset,account_id=null){
 if(!account_id)return chooseSystemAccount(asset,id=>approvalForm(asset,id));
 const reviewers=await api('/approvals/reviewers'),c=openModal('申请访问 '+asset.name);
 if(!reviewers.length){c.append(node('p','暂无可用审批人。请选择其他已启用且具有访问审批权限的用户；请联系权限管理员配置，不能审批自己的申请。','muted'));return;}
 const inputs=form(c,[['approver_id','审批人','select','',[['','请选择审批人'],...reviewers.map(u=>[u.id,u.username])]],['reason','运维原因（至少 5 字）','textarea'],['hours','访问时长（1–8 小时）','number',1]],async data=>{
  if(!data.approver_id)throw Error('请选择审批人');
  await api('/approvals','POST',{...data,asset_id:asset.id,account_id});$('modal').close();await show('approvals');notify('申请已提交，等待 '+reviewers.find(u=>u.id===data.approver_id).username+' 审批。');
 },'提交申请');
 inputs.approver_id.required=true;inputs.reason.required=true;inputs.reason.minLength=5;inputs.reason.maxLength=1000;inputs.hours.min=1;inputs.hours.max=8;
 
}
pages.approvals=async root=>{const rows=await api('/approvals');actions(root,button('刷新',()=>show('approvals'),'secondary'));root.append(table(rows,[['username','申请用户'],['asset_id','资产 ID'],['system_username','系统账号'],['approver_name','指定审批人',row=>node('span',row.approver_name||(row.approver_id?'审批人不可用':'任一其他管理员（历史申请）'))],['reviewer_name','实际审批人'],['reason','申请原因'],['state','状态'],['expires_at','到期时间']],row=>hasPermission('approvals.review')&&row.state==='pending'&&row.user_id!==me.id&&(!row.approver_id||row.approver_id===me.id)&&new Date(row.expires_at)>new Date()?[button('通过',async()=>{await api('/approvals/'+row.id+'/decide','POST',{approve:true});await show('approvals');}),button('拒绝',async()=>{await api('/approvals/'+row.id+'/decide','POST',{approve:false});await show('approvals');},'danger')]:[]));};
async function nativeSsh(asset,account_id=null){
 if(!account_id)return chooseSystemAccount(asset,id=>nativeSsh(asset,id));
 const owner=me,generation=connectionGeneration;
 const result=await api('/native-ssh/sessions','POST',{asset_id:asset.id,account_id});
 if(owner!==me||generation!==connectionGeneration)return;
 const c=openModal('SSH 客户端 · '+asset.name);
 c.append(node('p','30 秒内连接，票据仅能启动一次会话。使用 SSH 客户端的密码认证，密码填写下方临时票据；请勿使用资源密码。','muted'));
 c.append(node('pre','ssh -tt -p '+result.port+' -l '+result.username+' '+location.hostname));
 if(result.host_key_fingerprint)c.append(node('p','堡垒机主机公钥指纹：'+result.host_key_fingerprint,'muted'));
 const label=node('label','临时连接票据'),value=node('textarea');value.value=result.password;value.readOnly=true;label.append(value);c.append(label);
 c.append(node('p','首次连接请核对堡垒机主机公钥指纹。仅支持交互终端，沿用现有审批、命令策略及录像。','muted'));
}
async function connect(asset,account_id=null){if(!account_id)return chooseSystemAccount(asset,id=>connect(asset,id));const owner=me,generation=connectionGeneration;const result=await api('/sessions','POST',{asset_id:asset.id,account_id});if(owner!==me||generation!==connectionGeneration){await api('/sessions/'+result.id+'/terminate','POST',{}).catch(()=>{});return;}if(!['ssh','telnet'].includes(result.protocol))return connectProtocol(asset,result);const c=openModal(result.protocol.toUpperCase()+' · '+asset.name+' / '+result.system_username);c.append(node('p','输出已加密录制。关闭窗口将断开连接。','muted'));const box=node('div',undefined,'terminal');c.append(box);terminal=new Terminal({cols:100,rows:28,cursorBlink:true,theme:{background:'#10151e'},fontSize:13,scrollback:3000});terminal.open(box);if(result.protocol==='ssh')attachSftpSheets(c,box,asset,account_id);socket=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+result.websocket);socket.onopen=()=>{socket.send(JSON.stringify({ticket:result.ticket}));terminal.focus();};socket.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='output')terminal?.write(m.data);if(m.type==='closed')terminal?.writeln('\r\n['+m.message+']');};socket.onclose=()=>terminal?.writeln('\r\n[连接已断开]');terminal.onData(data=>{if(socket?.readyState===WebSocket.OPEN)socket.send(JSON.stringify({type:'input',data}));});terminal.onResize(size=>{if(socket?.readyState===WebSocket.OPEN)socket.send(JSON.stringify({type:'resize',...size}));});}
pages.sessions=async root=>{const rows=await api('/sessions');actions(root,button('刷新会话',()=>show('sessions'),'secondary'));root.append(table(rows,[['username','平台用户'],['asset','资产'],['protocol','协议'],['system_username','资源系统账号'],['state','状态'],['created_at','开始时间'],['ended_at','结束时间'],['error','说明']],row=>{const ops=[];if(hasPermission('recordings.view'))ops.push(button('回放',()=>replay(row)));if(['active','pending'].includes(row.state)&&hasPermission('sessions.terminate')&&(row.username===me.username||hasPermission('sessions.terminate_all')))ops.push(button('终止',()=>confirmAction('终止会话','确认终止此会话？',()=>api('/sessions/'+row.id+'/terminate','POST',{}),()=>show('sessions'),'确认终止'),'danger'));return ops;}));};
async function replay(row){if(!['ssh','telnet'].includes(row.protocol||'ssh'))return replayProtocol(row);const events=await api('/sessions/'+row.id+'/recording');const c=openModal('会话录像 · '+row.asset);c.append(node('p','终端输出包含远端回显；录像可能包含业务敏感信息，请按审计制度管理。','muted'));const box=node('div',undefined,'terminal');c.append(box);terminal=new Terminal({cols:100,rows:28,disableStdin:true,theme:{background:'#10151e'},fontSize:13,scrollback:10000});terminal.open(box);actions(c,button('按原始时间回放',()=>{for(const t of replayTimers)clearTimeout(t);terminal.reset();for(const event of events)replayTimers.push(setTimeout(()=>terminal?.write(event.data),event.ms));}),button('显示完整输出',()=>{for(const t of replayTimers)clearTimeout(t);terminal.reset();for(const event of events)terminal.write(event.data);},'secondary'));if(!events.length)c.append(node('p','暂无录制输出'));}
pages.audit=async root=>{let page=1;const data=node('div');async function load(){const rows=await api('/audit?page='+page);data.replaceChildren(table(rows,[['id','序号'],['actor_id','操作者 ID'],['action','操作'],['target','对象'],['ip','来源 IP'],['created_at','时间']]));}actions(root,button('上一页',async()=>{page=Math.max(1,page-1);await load();},'secondary'),button('下一页',async()=>{page++;await load();},'secondary'));root.append(data);await load();};
pages.password=async root=>{const c=card('修改密码');form(c,[['old_password','原密码','password'],['new_password','新密码（至少 12 位）','password']],async data=>{await api('/auth/password','POST',data);me=null;loginView();notify('密码已修改，请重新登录。');});root.append(c);};
labels.settings='系统配置';
let platform={};
const fonts={system:'system-ui,"Microsoft YaHei",sans-serif',yahei:'"Microsoft YaHei",sans-serif',simsun:'SimSun,"Songti SC",serif',mono:'Consolas,"Microsoft YaHei",monospace'};
function applyPlatform(data){
 platform=data;document.title=data.platform_name;
 const brand=document.querySelector('.brand');brand.replaceChildren();
 if(data.logo){const img=node('img');img.src=data.logo;img.alt='平台 LOGO';img.className='platform-logo';brand.append(img);}
 brand.append(node('span',data.platform_name,'platform-name'));
 document.querySelector('aside>p').textContent=data.subtitle;
 document.querySelector('header small').textContent=data.platform_name;
 document.documentElement.dataset.theme=data.theme;
 document.documentElement.style.setProperty('--primary',data.primary_color);
 document.documentElement.style.fontFamily=fonts[data.font]||fonts.system;
 document.documentElement.style.fontSize=data.font_size+'px';
}
async function loadPlatform(){applyPlatform(await api('/platform'));}
pages.settings=async root=>{
 if(!menuAllowed(current))throw Error('没有平台权限');
 await loadPlatform();
 const appearance=card('平台外观'),currentSettings={...platform};appearance.classList.add('appearance-settings');
 appearance.append(node('p','平台名称、LOGO、风格和字体保存后立即生效，登录页也使用这些设置。','muted'));
 let logo=platform.logo;
 const inputs=form(appearance,[['platform_name','平台名称','text',platform.platform_name],['subtitle','平台说明','text',platform.subtitle],['theme','页面风格','select',platform.theme,[['light','明亮'],['dark','深色']]],['primary_color','主题颜色','color',platform.primary_color],['font','字体','select',platform.font,[['system','系统默认'],['yahei','微软雅黑'],['simsun','宋体'],['mono','等宽字体']]],['font_size','字号（12～20px）','number',platform.font_size]],async data=>{
  applyPlatform(await api('/settings/appearance','PUT',{...data,logo}));notify('平台外观已保存并生效');
 },'保存外观');
 inputs.font_size.min=12;inputs.font_size.max=20;inputs.platform_name.required=true;
 const logoBox=node('div',undefined,'logo-editor'),preview=node('img');preview.className='logo-preview';preview.alt='LOGO 预览';
 const renderLogo=()=>{preview.hidden=!logo;if(logo)preview.src=logo;else preview.removeAttribute('src');};renderLogo();
 const upload=node('input');upload.type='file';upload.accept='image/png,image/jpeg,image/webp';upload.setAttribute('aria-label','上传 LOGO');
 upload.onchange=async()=>{try{
  const file=upload.files[0];if(!file)return;
  if(!['image/png','image/jpeg','image/webp'].includes(file.type))throw Error('请选择 PNG、JPEG 或 WebP 图片');
  if(file.size>5*1024*1024)throw Error('请选择 5MB 以内的图片');
  const bitmap=await createImageBitmap(file),canvas=document.createElement('canvas');
  const scale=Math.min(1,256/Math.max(bitmap.width,bitmap.height));canvas.width=Math.max(1,Math.round(bitmap.width*scale));canvas.height=Math.max(1,Math.round(bitmap.height*scale));
  canvas.getContext('2d').drawImage(bitmap,0,0,canvas.width,canvas.height);bitmap.close();
  const candidate=canvas.toDataURL('image/webp',0.85);if(candidate.length>43720)throw Error('图片压缩后仍过大，请使用更简洁的 LOGO');
  logo=candidate;renderLogo();notify('LOGO 已选取，请点击“保存外观”');
 }catch(e){notify(e.message);}finally{upload.value='';}};
 logoBox.append(node('label','平台 LOGO'),preview,upload,node('p','支持 PNG、JPEG、WebP，上传时自动缩小至 256px，保存后显示在侧栏和登录页。','muted'));
 const appearanceActions=appearance.querySelector('form > .actions');appearanceActions.classList.add('appearance-actions');
 appearanceActions.before(logoBox);
 appearanceActions.prepend(button('移除 LOGO',()=>{logo='';renderLogo();},'secondary'));
 appearanceActions.append(button('预览外观',()=>{const data={};for(const [key,input] of Object.entries(inputs))data[key]=input.type==='number'?Number(input.value):input.value;applyPlatform({...data,logo});},'secondary'),button('取消预览',()=>applyPlatform(currentSettings),'secondary'));
 if(hasPermission('settings.appearance'))root.append(appearance);
 if(hasPermission('settings.logging')){const logging=card('');root.append(logging);await renderLogForwarding(logging,api,'/settings/logging');}
 if(!hasPermission('settings.database'))return;
 const db=await api('/settings/database'),database=card('PostgreSQL 数据库');database.classList.add('database-settings');
 database.append(node('p','当前连接：'+db.active.host+':'+db.active.port+' / '+db.active.database+'（用户：'+db.active.username+'）','muted'));
 const state=node('p',db.restart_required?'存在待生效配置，请重启服务后检查连接。':'当前配置已生效。','muted');database.append(state);
 database.append(node('p','密码留空保留已配置密码。可先测试连接；更换数据库前需迁移原库数据及加密主密钥，保存后重启服务生效。','muted'));
 const configured=db.configured;
 const dbInputs=form(database,[['host','数据库地址','text',configured.host],['port','端口','number',configured.port],['database','数据库名称','text',configured.database],['username','数据库用户','text',configured.username],['password','数据库密码（留空保留）','password'],['sslmode','SSL 模式','select',configured.sslmode,[['disable','禁用'],['prefer','优先使用'],['require','必须使用'],['verify-ca','校验 CA'],['verify-full','完整校验']]]],async data=>{
  const result=await api('/settings/database','PUT',data);dbInputs.password.value='';state.textContent=result.message;notify(result.message);
 },'保存数据库配置');
 const dbData=()=>Object.fromEntries(Object.entries(dbInputs).map(([key,input])=>[key,input.type==='number'?Number(input.value):input.value]));
 const testButton=button('测试连接',async()=>{const result=await api('/settings/database/test','POST',dbData());state.textContent='连接成功，PostgreSQL '+result.version+(result.schema_ready?'，平台数据表已就绪。':'，目标库尚无完整平台数据表，请先迁移原库数据并升级。');notify(state.textContent);},'secondary');
 const initializeButton=button('初始化数据库',async()=>{if(!confirm('初始化表单中的目标数据库？不切换连接，不迁移历史数据。空库创建当前操作用户的管理员账号；已有数据保留。'))return;initializeButton.disabled=true;try{const result=await api('/settings/database/initialize','POST',dbData());state.textContent=result.message;notify(result.message);}finally{initializeButton.disabled=false;}},'secondary');
 database.querySelector('form .actions').prepend(testButton,initializeButton);root.append(database);
};
const originalBoot=boot;
boot=async()=>{await Promise.all([loadPlatform().catch(e=>notify(e.message)),originalBoot()]);if(!menuAllowed('settings'))document.querySelector('nav button[data-page=settings]')?.remove();};
let approvalReminderBusy=false;
function stopApprovalReminders(){
 $('approval-reminder')?.remove();
}
function ensureApprovalReminder(){
 let reminder=$('approval-reminder');
 if(!reminder){
  reminder=button('',showApprovalMessages,'secondary approval-reminder');
  reminder.id='approval-reminder';
  const icon=node('span','📣','approval-reminder-icon');icon.setAttribute('aria-hidden','true');
  const count=node('span','0','approval-reminder-count');count.id='approval-reminder-count';
  reminder.append(icon,count);reminder.title='审批消息';reminder.setAttribute('aria-label','审批消息');
  $('identity').prepend(reminder);
 }
 return reminder;
}
async function refreshApprovalReminders(){
 if(!me||approvalReminderBusy)return;
 const reviewer=me.id;approvalReminderBusy=true;
 const reminder=ensureApprovalReminder();
 try{
  const data=await api('/notifications');
  if(me?.id!==reviewer)return;
  $('approval-reminder-count').textContent=data.count;
  reminder.setAttribute('aria-label','审批消息 '+data.count+' 条，点击查看');
  reminder.title='审批消息 '+data.count+' 条';
 }catch(e){
  if(me?.id===reviewer){reminder.title='消息加载失败，点击重试';$('approval-reminder-count').textContent='—';}
 }finally{approvalReminderBusy=false;}
}
const bootBeforeReminders=boot;
boot=async()=>{stopApprovalReminders();await bootBeforeReminders();};
async function showApprovalMessages(){
 const data=await api('/notifications');
 await refreshApprovalReminders();
 const c=openModal('审批消息');
 if(data.pending_count)actions(c,button('待我审批（'+data.pending_count+'）',async()=>{$('modal').close();await show('approvals');}));
 if(data.results.length){
  c.append(node('h3','我的申请审批结果'));
  c.append(table(data.results,[['asset_name','资源'],['system_username','系统账号'],['reviewer_name','审批人'],['state','审批结果',row=>node('span',row.state==='approved'?'通过':'不通过',row.state==='approved'?'approval-result-approved':'approval-result-rejected')]],row=>[button('标为已读',async()=>{await api('/notifications/approvals/'+row.id+'/read','POST',{});await showApprovalMessages();},'secondary')]));
 }
 if(!data.count)c.append(node('p','暂无新消息'));
}
const loginBeforeReminders=loginView;
loginView=()=>{stopApprovalReminders();closeTerminal();if($('modal').open)$('modal').close();loginBeforeReminders();};
const approvalsBeforeReminders=pages.approvals;
pages.approvals=async root=>{await approvalsBeforeReminders(root);await refreshApprovalReminders();};
labels.roles='角色管理';
labels.permissions='权限管理';
labels.commandAudit='命令审计';
pages.commandAudit=root=>protocolAuditView(root,'',true);
const commandModeNames={off:'不限制',deny:'黑名单',allow:'白名单'};
function policyFields(row={}){
 return [['command_mode','SSH / TELNET 命令策略','select',row.command_mode||'off',Object.entries(commandModeNames)],['command_rules_text','命令规则（每行一条）','textarea',(row.command_rules||[]).join('\n')]];
}
function policyPayload(data){
 const {command_rules_text,...other}=data;
 return {...other,command_rules:(command_rules_text||'').split(/\r?\n/).map(s=>s.trim()).filter(Boolean)};
}
function policyHelp(parent){
 parent.append(node('p','规则示例：rm 表示该命令及全部参数；ls * 表示匹配带参数的 ls；支持 *、? 通配符，区分大小写。白名单为空时拒绝全部命令。角色和用户的黑名单共同拒绝，启用的白名单均须匹配。','muted'));
 parent.append(node('p','仅作用于 SSH / TELNET，不影响 SQL。启用后改为逐条命令模式，不支持交互程序、解释器、管道、重定向、历史或补全。SSH 每条命令使用独立环境；规则变更会终止受影响的会话，重连生效。','muted'));
 parent.append(node('p','命令规则只控制网关提交的命令，不能替代目标系统权限。生产限制建议使用精确白名单及权限受限的系统账号；用户自建程序、远端别名或程序内部行为仍需由目标系统约束。','muted'));
}
function editUserCommandPolicy(row,roles){
 const c=openModal('命令黑 / 白名单 · '+row.username),role=roles.find(r=>r.id===row.role_id);
 c.append(node('p','所属角色：'+(role?.name||row.role_name||row.role)+'；角色策略：'+(commandModeNames[role?.command_mode]||'不限制')+(role?.command_rules?.length?'（'+role.command_rules.join('、')+'）':''),'muted'));
 policyHelp(c);
 form(c,policyFields(row),async data=>{await api('/users/'+row.id+'/command-policy','PUT',policyPayload(data));$('modal').close();await show('users');notify('用户命令策略已保存，受影响会话已终止，请重新连接。');},'保存命令策略');
}
function editRole(row={}){
 const c=openModal(row.id?'编辑角色 · '+row.name:'新增角色');
 c.append(node('p','权限类型提供新角色的默认权限。创建后可通过“权限管理”逐项分配平台权限；具体能力以已分配权限为准。内置角色保留原权限类型。','muted'));policyHelp(c);
 const fields=form(c,[['name','角色名称','text',row.name||''],['base_role','权限类型','select',row.base_role||'operator',Object.entries(roleNames)],['description','说明','textarea',row.description||''],...policyFields(row)],async data=>{
  await api('/roles'+(row.id?'/'+row.id:''),row.id?'PUT':'POST',policyPayload(data));$('modal').close();await show('roles');notify('角色已保存；权限或命令策略变更会终止受影响会话。');
 },'保存角色');
 fields.name.required=true;fields.name.maxLength=80;fields.description.maxLength=300;fields.base_role.disabled=!!row.builtin;
}
pages.roles=async root=>{
 const rows=await api('/roles');actions(root,button('新增角色',()=>editRole()),button('刷新',()=>show('roles'),'secondary'));
 root.append(table(rows,[['name','角色名称'],['base_role','权限类型',r=>node('span',roleNames[r.base_role])],['description','说明'],['user_count','用户数'],['command_mode','命令策略',r=>node('span',commandModeNames[r.command_mode])],['command_rules','规则',r=>node('pre',r.command_rules.join('\n'),'audit-detail')]],r=>{
  const ops=[button('编辑',()=>editRole(r),'secondary'),button('分配平台权限',()=>{window.permissionRoleId=r.id;return show('permissions');},'secondary')];
  if(!r.builtin)ops.push(button('删除',()=>{const c=openModal('删除角色 · '+r.name);c.append(node('p','确认删除此角色？已分配给用户的角色需先解除分配。'));actions(c,button('确认删除',async()=>{await api('/roles/'+r.id,'DELETE');$('modal').close();await show('roles');},'danger'));},'danger'));
  return ops;
 }));
};
pages.permissions=async root=>{
 const [catalog,roles]=await Promise.all([api('/permissions'),api('/roles')]);
 const panel=card('角色平台权限分配');
 panel.append(node('p','选择角色并勾选平台功能权限。用户通过所属角色获得权限；资源账号授权、访问审批和命令黑／白名单仍单独检查。勾选操作权限会自动勾选所需的查看权限。','muted'));
 panel.append(node('p','“审计 → 会话与录像”需授予“查看全部会话”或“查看全部会话录像”。“查看自己的会话”不授予审计菜单；命令、SQL / 协议及操作审计分别授权。','muted'));
 const selector=node('select');selector.setAttribute('aria-label','选择权限角色');
 for(const role of roles){const option=node('option',role.name+'（'+roleNames[role.base_role]+'）');option.value=role.id;selector.append(option);}
 selector.value=roles.some(r=>r.id===window.permissionRoleId)?window.permissionRoleId:(roles.find(r=>r.id!=='admin')?.id||roles[0]?.id||'');
 const label=node('label','角色');label.append(selector);panel.append(label);
 const message=node('p',undefined,'muted'),groups=node('div',undefined,'permission-groups'),summary=node('p',undefined,'muted');
 const checks=new Map();let selected,locked=false;
 const dependencies=new Map(catalog.items.map(item=>[item.code,item.requires||[]]));
 const updateSummary=()=>{summary.textContent='已选 '+[...checks.values()].filter(check=>check.checked).length+' / '+catalog.items.length+' 项权限';};
 const addRequired=code=>{const input=checks.get(code);if(input&&!input.checked){input.checked=true;for(const dep of dependencies.get(code)||[])addRequired(dep);}};
 const removeDependent=()=>{let changed=true;while(changed){changed=false;for(const [code,input]of checks)if(input.checked&&(dependencies.get(code)||[]).some(dep=>!checks.get(dep)?.checked)){input.checked=false;changed=true;}}};
 const render=()=>{
  selected=roles.find(r=>r.id===selector.value);if(!selected)return;
  window.permissionRoleId=selected.id;checks.clear();groups.replaceChildren();
  const self=(me.role_id||me.role)===selected.id;
  const superior=(selected.permissions||[]).some(code=>!hasPermission(code));
  locked=!!selected.permissions_locked||selected.id==='admin'||self||superior;
  message.textContent=selected.id==='admin'?'内置管理员保留全部权限。请创建自定义角色配置受限权限。':self?'不能修改自己所属角色的权限，请由其他权限管理员操作。':superior?'该角色拥有超出您自身范围的权限，只可查看。':'保存后该角色用户的现有登录和所有协议会话会失效，重新登录后生效。';
  const sections=new Map();
  for(const item of catalog.items){
   if(!sections.has(item.group)){const box=node('fieldset',undefined,'permission-group');box.append(node('legend',item.group));sections.set(item.group,box);groups.append(box);}
   const option=node('label',undefined,'permission-option'),input=node('input');input.type='checkbox';input.value=item.code;input.checked=(selected.permissions||[]).includes(item.code);input.disabled=locked||!hasPermission(item.code);input.setAttribute('aria-label',item.label);
   input.onchange=()=>{if(input.checked){for(const dep of dependencies.get(item.code)||[])addRequired(dep);}else removeDependent();updateSummary();};
   option.append(input,node('span',item.label));sections.get(item.group).append(option);checks.set(item.code,input);
  }
  save.disabled=locked;for(const button of tools.children)button.disabled=locked;updateSummary();
 };
 const tools=actions(panel,button('全选可分配权限',()=>{for(const [code,input]of checks)if(!input.disabled)addRequired(code);updateSummary();},'secondary'),button('清空权限',()=>{for(const input of checks.values())if(!input.disabled)input.checked=false;updateSummary();},'secondary'),button('使用权限类型默认值',()=>{const codes=catalog.defaults[selected.base_role]||[];for(const [code,input]of checks)if(!input.disabled)input.checked=codes.includes(code);updateSummary();},'secondary'));
 const save=button('保存平台权限',async()=>{
  if(locked)return;const target=selected;const data=await api('/roles/'+target.id+'/permissions','PUT',{permissions:[...checks].filter(([,input])=>input.checked).map(([code])=>code)});
  Object.assign(target,data);render();notify('角色平台权限已保存，相关用户需重新登录。');
 });
 panel.append(message,groups,summary);actions(panel,save);selector.onchange=render;root.append(panel);render();
};
boot().catch(e=>notify(e.message));

const renderSystemSettings=pages.settings;
pages.settings=async root=>{
 const panels=node('div');await renderSystemSettings(panels);
 const sheets=[...panels.children];if(!sheets.length)return;
 const tabs=node('div',undefined,'settings-tabs');tabs.setAttribute('role','tablist');root.append(tabs,panels);
 const buttons=[];
 sheets.forEach((sheet,index)=>{
  const title=sheet.querySelector('h2,h3')?.textContent||'Settings';
  const tab=button(title,()=>select(index),'secondary');tab.setAttribute('role','tab');tab.id='settings-tab-'+index;
  sheet.id='settings-sheet-'+index;sheet.setAttribute('role','tabpanel');sheet.setAttribute('aria-labelledby',tab.id);tab.setAttribute('aria-controls',sheet.id);
  tabs.append(tab);buttons.push(tab);
 });
 function select(index){sheets.forEach((sheet,i)=>{sheet.hidden=i!==index;buttons[i].setAttribute('aria-selected',String(i===index));});}select(0);
};
