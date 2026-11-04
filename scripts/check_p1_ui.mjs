// Synthetic UI fixtures only. All API requests are intercepted; no email or real data writes.
import { chromium } from '../frontend/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
const browser = await chromium.launch({channel: 'msedge', headless: true});
try {
  const page = await browser.newPage();
  const user = {id:1,name:'Fixture',email:'staff@onesmarter.com',role:'staff',can_nophi:true,sender_addresses:['staff@onesmarter.com'],organization:'Fixture'};
  let submitted;
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if(path === '/api/auth/session') return route.fulfill({json:{csrf:'',user,setup_required:false}});
    if(path === '/api/document-service') return route.fulfill({json:{ready:true}});
    if(path === '/api/routing/preview') {
      const data=route.request().postDataJSON();
      await new Promise(resolve=>setTimeout(resolve,250));
      return route.fulfill({json:{protected:!data.nophi_override,reason:data.nophi_override?'explicit_nophi_override':'external_recipient'}});
    }
    if(path === '/api/conversations' && route.request().method()==='POST') {
      submitted=route.request().postDataJSON();
      return route.fulfill({json:{id:'fixture'}});
    }
    return route.fulfill({json:{results:[],messages:[],recipients:[]}});
  });
  await page.goto('http://localhost:5173/staff/#/compose');
  await page.getByPlaceholder('recipient@example.com').first().fill('sara@example.test');
  await page.getByPlaceholder('recipient@example.com').first().press('Tab');
  await page.getByLabel('Subject',{exact:true}).fill('A normal subject');
  await page.getByLabel('Message',{exact:true}).fill('Synthetic draft');
  const protectedSend=page.getByRole('button',{name:'Send protected',exact:true});
  await protectedSend.waitFor();
  await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.includes('Send protected')&&!b.disabled));
  await page.getByLabel('Subject',{exact:true}).fill('Nophi is only a word');
  assert.equal(await protectedSend.isDisabled(),true);
  await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.includes('Send protected')&&!b.disabled));
  await page.getByLabel('Use Nophi: send as normal email').check();
  const normalSend=page.getByRole('button',{name:'Send normal email',exact:true});
  await normalSend.waitFor();
  assert.equal(await normalSend.isDisabled(),true);
  await page.getByLabel('I understand that the content and attachments will be emailed and cannot be recalled through the portal.').check();
  await page.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.includes('Send normal email')&&!b.disabled));
  const addressInput=page.locator('#addresses-To');
  await addressInput.fill('not-an-email');
  await normalSend.click();
  assert.equal(submitted,undefined);
  assert.equal(await addressInput.evaluate(el=>el.checkValidity()),false);
  await addressInput.fill('');
  await addressInput.press('Tab');
  await normalSend.click();
  assert.equal(submitted.nophi_override,true);
  assert.equal(submitted.nophi_acknowledged,true);
  assert.deepEqual(submitted.expected_route,{protected:false,reason:'explicit_nophi_override'});

  const visitor=await browser.newPage({viewport:{width:360,height:800}});
  await visitor.clock.install();
  let expired=false;
  const conversation={id:'fixture',subject:'Synthetic request',messages:[],recipients:[],protected:true};
  await visitor.route('**/recipient-api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith('/auth/session'))return route.fulfill({json:{csrf:'',user:null}});
    if(path.endsWith('/document-service'))return route.fulfill({json:{ready:true}});
    if(path.endsWith('/landing'))return route.fulfill({json:{organization:'Fixture',recipient:'s***@example.test'}});
    if(path.endsWith('/code'))return route.fulfill({json:{sent:true}});
    if(path.endsWith('/verify')){expired=false;return route.fulfill({json:{verified:true}});}
    if(path.endsWith('/attachments'))return route.fulfill({json:{id:'file-fixture',name:'test.txt',size:4,state:'available'}});
    if(path.endsWith('/conversation'))return expired ? route.fulfill({status:401,json:{error:{code:'recipient_session_expired',message:'Verify again'}}}) : route.fulfill({json:conversation});
    if(path.endsWith('/activity'))return route.fulfill({json:{active:true}});
    throw new Error('Unexpected recipient request');
  });
  await visitor.goto('http://localhost:5173/recipient/#/invite/fixture');
  await visitor.getByRole('button',{name:'Email me a code',exact:true}).click();
  assert.equal(await visitor.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true);
  await visitor.getByLabel('Verification code').fill('123456');
  await visitor.getByRole('button',{name:'Verify & open',exact:true}).click();
  await visitor.waitForURL('**/#/conversation');
  assert.equal(new URL(visitor.url()).hash,'#/conversation');
  await visitor.getByLabel('Message',{exact:true}).fill('Draft survives verification');
  await visitor.getByLabel('Upload attachments').setInputFiles({name:'test.txt',mimeType:'text/plain',buffer:Buffer.from('test')});
  await visitor.getByRole('button',{name:'Remove test.txt'}).waitFor();
  assert.equal(await visitor.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true);
  expired=true;
  await visitor.clock.fastForward(61000);
  await visitor.getByLabel('Verification code').waitFor();
  assert.equal(await visitor.getByRole('heading',{name:'This message is unavailable'}).count(),0);
  await visitor.getByLabel('Verification code').fill('654321');
  await visitor.getByRole('button',{name:'Verify & open',exact:true}).click();
  await visitor.clock.runFor(500);
  assert.equal(await visitor.getByLabel('Message',{exact:true}).inputValue(),'Draft survives verification');
  await visitor.getByRole('button',{name:'Remove test.txt'}).waitFor();
  await visitor.reload();
  await visitor.getByRole('heading',{name:'Synthetic request',exact:true}).waitFor();
  await visitor.waitForURL('**/#/conversation');
  assert.equal(new URL(visitor.url()).hash,'#/conversation');
  const inbox=await browser.newPage();
  let inboxRequests=0;
  await inbox.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith('/auth/session'))return route.fulfill({json:{csrf:'',user,setup_required:false,dev_tools:true}});
    if(path.endsWith('/dev/inbox')){
      inboxRequests++;
      assert.equal(route.request().headers()['x-dev-inbox-token'],'synthetic-operator-capability-for-test');
      return route.fulfill({json:{results:[{id:'1',subject:'Synthetic captured message',to:'fixture@example.test',body:'Synthetic only',created_at:new Date().toISOString()}]}});
    }
    return route.fulfill({json:{results:[]}});
  });
  await inbox.goto('http://localhost:5173/staff/#/development/inbox');
  await inbox.getByLabel('Development inbox token').waitFor();
  assert.equal(inboxRequests,0);
  await inbox.getByLabel('Development inbox token').fill('synthetic-operator-capability-for-test');
  await inbox.getByRole('button',{name:'Unlock inbox',exact:true}).click();
  await inbox.getByText('Synthetic captured message',{exact:true}).waitFor();
  assert.equal(await inbox.getByLabel('Development inbox token').inputValue(),'');
  await inbox.getByRole('button',{name:'Lock inbox',exact:true}).click();
  await inbox.getByText('Synthetic captured message',{exact:true}).waitFor({state:'hidden'});
  console.log('Stale preview blocked; explicit Nophi acknowledged; expected route submitted; recipient 401 re-verification retained draft and uploaded file. No real writes.');
} finally {await browser.close();}
