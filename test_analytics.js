const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const code = fs.readFileSync(path.join(__dirname, '../static/analytics.js'), 'utf8');
function run({result='none',stored=null,gpc=false,dnt='0',storageThrows=false}={}) {
  const control={checked:true,addEventListener:(n,f)=>control[n]=f};
  const status={textContent:''};
  const form={addEventListener:(n,f)=>form[n]=f};
  const links=['logo','footer'].map(p=>({dataset:{fdfLink:p},addEventListener(n,f){this[n]=f;}}));
  const loaded=[];
  const window={location:{href:'https://checker.invalid/?secret=PRIVATE#PRIVATE'}};
  const context={window,navigator:{globalPrivacyControl:gpc,doNotTrack:dnt},URL,Date,
    localStorage:{getItem(){if(storageThrows)throw Error('blocked');return stored;},setItem(k,v){if(storageThrows)throw Error('blocked');stored=v;}},
    document:{referrer:'https://www.frederickdataforensics.net/private?token=PRIVATE',body:{dataset:{checkStatus:result}},
      getElementById:id=>id==='usage-analytics'?control:status,
      querySelector:selector=>{assert.equal(selector,'.checker-form');return form;},
      querySelectorAll:selector=>{assert.equal(selector,'[data-fdf-link]');return links;},
      createElement:()=>({}),head:{appendChild:s=>loaded.push(s)}}};
  vm.runInNewContext(code,context);
  return {window,control,status,form,links,loaded};
}
function events(x){return Array.from(x.window.dataLayer||[],a=>Array.from(a)).filter(a=>a[0]==='event');}
let x=run({result:'completed'});x.form.submit();x.links[0].click();
assert.deepEqual(events(x).map(a=>a[1]),['page_view','check_completed','check_submitted','fdf_website_click']);
assert.equal(x.loaded.length,1);assert.equal(x.loaded[0].referrerPolicy,'no-referrer');
for(const [,name,payload] of events(x)){
 assert.equal(payload.page_location,'https://domain-spoof-detector-834650413835.europe-west1.run.app/');
 assert.equal(payload.page_referrer,'');
 assert(!JSON.stringify(payload).includes('PRIVATE'));
 const allowed=['page_location','page_referrer','page_title','send_to','entry_source','failure_kind','link_placement'];
 assert(Object.keys(payload).every(k=>allowed.includes(k)));
}
assert(!JSON.stringify(x.window.dataLayer.map(a=>Array.from(a))).includes('PRIVATE'));
const config=x.window.dataLayer.map(a=>Array.from(a)).find(a=>a[0]==='config')[2];
assert.equal(config.send_page_view,false);assert.equal(config.allow_google_signals,false);
assert.equal(config.allow_ad_personalization_signals,false);
x.control.checked=false;x.control.change();const count=events(x).length;x.form.submit();x.links[1].click();assert.equal(events(x).length,count);
for(const options of [{stored:'off'},{gpc:true},{dnt:'1'}]){x=run(options);x.form.submit();assert.equal(x.loaded.length,0);assert.equal(events(x).length,0);}
x=run({stored:'off'});x.control.checked=true;x.control.change();assert.equal(x.loaded.length,1);
x=run({result:'failed',storageThrows:true});assert(events(x).some(a=>a[1]==='check_failed'));x.control.checked=false;x.control.change();assert.equal(x.window['ga-disable-G-45BCG2QEE8'],true);
console.log('Analytics event, metadata, opt-out and privacy-signal tests passed.');
