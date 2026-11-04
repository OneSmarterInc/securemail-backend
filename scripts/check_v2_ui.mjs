// Synthetic browser regression: intercept every API request; never sends real mail.
import { chromium } from '../frontend/node_modules/playwright/index.mjs';
import { expect } from '../frontend/node_modules/@playwright/test/index.mjs';
import assert from 'node:assert/strict';
const browser = await chromium.launch({channel:'msedge',headless:true});
try {
  const page = await browser.newPage();
  let codes=0;let uploads=0;
  const keys=[];
  const conversation={id:'fixture',subject:'Synthetic request',mode:'secure_request',protected:true,state:'open',created_at:new Date().toISOString(),expires_at:'2030-01-01T00:00:00Z',recipients:[],messages:[],delivery:[]};
  await page.route('**/recipient-api/**', async route => {
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith('/auth/session'))return route.fulfill({json:{csrf:'fixture',user:null}});
    if(path.endsWith('/document-service'))return route.fulfill({json:{ready:true}});
    if(path.endsWith('/landing'))return route.fulfill({json:{organization:'Fixture',recipient:'s***@example.test'}});
    if(path.endsWith('/code')){codes++;return route.fulfill({json:{sent:true}});}
    if(path.endsWith('/attachments')){
      uploads++;
      if(uploads===1)return route.fulfill({json:{id:'accepted-file',name:'first.txt',size:4,state:'available'}});
      return route.fulfill({status:401,json:{error:{code:'recipient_session_expired',message:'Verify again'}}});
    }
    if(path.endsWith('/conversation')){
      if(route.request().method()==='POST')keys.push(route.request().headers()['idempotency-key']);
      return route.fulfill({json:conversation});
    }
    return route.fulfill({json:{verified:true}});
  });
  await page.goto('http://localhost:5173/recipient/#/invite/synthetic');
  await page.getByRole('button',{name:'Email me a code'}).click();
  await page.getByLabel('Verification code').fill('123456');
  await page.getByRole('button',{name:'Verify & open'}).click();
  await page.getByLabel('Message',{exact:true}).fill('Draft retained through expiry');
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent('session-expired')));
  await expect(page.getByLabel('Verification code')).toBeVisible();
  await expect.poll(()=>codes).toBe(2);
  await page.getByLabel('Verification code').fill('654321');
  await page.getByRole('button',{name:'Verify & open'}).click();
  await expect(page.getByLabel('Message',{exact:true})).toHaveValue('Draft retained through expiry');
  for(let i=0;i<2;i++){
    await page.getByLabel('Message',{exact:true}).fill('Thanks');
    await page.getByRole('button',{name:'Submit reply'}).click();
    await expect(page.getByLabel('Message',{exact:true})).toHaveValue('');
  }
  assert.equal(keys.length,2);assert.notEqual(keys[0],keys[1]);
  await page.getByLabel('Upload attachments').setInputFiles([
    {name:'first.txt',mimeType:'text/plain',buffer:Buffer.from('test')},
    {name:'second.txt',mimeType:'text/plain',buffer:Buffer.from('test')}
  ]);
  await expect(page.getByLabel('Verification code')).toBeVisible();
  await expect.poll(()=>codes).toBe(3);
  await page.getByLabel('Verification code').fill('654321');
  await page.getByRole('button',{name:'Verify & open'}).click();
  await expect(page.getByRole('button',{name:'Remove first.txt'})).toBeVisible();

  const staff=await browser.newPage();let previews=0;let sends=0;
  await staff.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path.endsWith('/auth/session'))return route.fulfill({json:{csrf:'',user:{id:1,name:'Fixture',email:'staff@onesmarter.com',role:'staff',sender_addresses:['staff@onesmarter.com']}}});
    if(path.endsWith('/document-service'))return route.fulfill({json:{ready:true}});
    if(path.endsWith('/routing/preview')){previews++;return route.fulfill({json:{protected:true,reason:'external_recipient'}});}
    if(path.endsWith('/conversations')&&route.request().method()==='POST'){
      sends++;
      return sends===1?route.fulfill({status:409,json:{error:{code:'route_changed',message:'Review route'}}}):route.fulfill({json:{id:'fixture'}});
    }
    return route.fulfill({json:{...conversation,results:[]}});
  });
  await staff.goto('http://localhost:5173/staff/#/compose');
  await staff.getByPlaceholder('recipient@example.com').first().fill('sara@example.test');
  await staff.getByPlaceholder('recipient@example.com').first().press('Tab');
  await staff.getByLabel('Subject',{exact:true}).fill('Fixture');
  await staff.getByLabel('Message',{exact:true}).fill('Fixture');
  const send=staff.getByRole('button',{name:'Send protected',exact:true});
  await expect(send).toBeEnabled();const before=previews;
  await send.click();await expect.poll(()=>previews).toBeGreaterThan(before);
  await expect(send).toBeEnabled();await send.click();
  await expect.poll(()=>sends).toBe(2);
  console.log('PASS: automatic re-verification, draft retention, distinct reply keys, accepted upload survives 401, route conflict refresh');
}finally{await browser.close();}
