import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Technique = {
  name: string;
  source: string;
  style?: string;
  script?: string;
  before?: string;
  wrapStart?: string;
  wrapEnd?: string;
  body?: string;
};

const here = dirname(fileURLToPath(import.meta.url));
const pagesDir = join(here, 'pages');

const form = (inputAttrs: string, wrapStart: string, wrapEnd: string): string =>
  `<form id="f" method="post" action="#">${wrapStart}<input id="u" name="username" autocomplete="username" ${inputAttrs}>${wrapEnd}<input id="p" name="password" type="password" autocomplete="current-password"><button type="submit">Sign in</button></form>`;

export const techniques: Technique[] = [
  { name: 'benign', source: 'control: plain login form, menu must open and fill' },
  {
    name: 'opacity-self',
    source: 'DEF CON 33 element-level opacity: the target input is nearly transparent',
    style: '#u{opacity:.01}',
  },
  {
    name: 'opacity-parent',
    source: 'DEF CON 33 parent-level opacity: an ancestor of the target is transparent',
    wrapStart: '<div style="opacity:0">',
    wrapEnd: '</div>',
  },
  {
    name: 'opacity-body-after-show',
    source: 'body becomes transparent after the menu is shown',
    script: 'window.attack=()=>{document.body.style.opacity="0.01"}',
  },
  {
    name: 'opacity-root-after-show',
    source: 'DEF CON 33 root-level opacity: html becomes transparent after the menu is shown',
    script: 'window.attack=()=>{document.documentElement.style.opacity="0.01"}',
  },
  {
    name: 'filter-parent',
    source: 'CSS filter opacity(0) on an ancestor of the target',
    wrapStart: '<div style="filter:opacity(0)">',
    wrapEnd: '</div>',
  },
  {
    name: 'filter-root-after-show',
    source: 'CSS filter on html after the menu is shown',
    script: 'window.attack=()=>{document.documentElement.style.filter="blur(8px)"}',
  },
  {
    name: 'backdrop-filter-parent',
    source: 'backdrop-filter on an ancestor of the target',
    wrapStart: '<div style="backdrop-filter:blur(2px)">',
    wrapEnd: '</div>',
  },
  {
    name: 'blend-mode-self',
    source: 'mix-blend-mode on the target',
    style: '#u{mix-blend-mode:screen}',
  },
  {
    name: 'clip-path-parent',
    source: 'clip-path hides the target ancestor',
    wrapStart: '<div style="clip-path:inset(100%)">',
    wrapEnd: '</div>',
  },
  {
    name: 'mask-parent',
    source: 'CSS mask hides the target ancestor',
    wrapStart:
      '<div style="-webkit-mask-image:linear-gradient(transparent,transparent);mask-image:linear-gradient(transparent,transparent)">',
    wrapEnd: '</div>',
  },
  {
    name: 'transform-shrink',
    source: 'transform scale shrinks the target ancestor',
    wrapStart: '<div style="transform:scale(.01);transform-origin:0 0">',
    wrapEnd: '</div>',
  },
  {
    name: 'transform-offscreen',
    source: 'transform moves the target ancestor off the viewport',
    wrapStart: '<div style="transform:translateX(-5000px)">',
    wrapEnd: '</div>',
  },
  {
    name: 'pointer-events-none',
    source: 'target has pointer-events none',
    style: '#u{pointer-events:none}',
  },
  {
    name: 'tiny-target',
    source: 'target is 1x1 px',
    style: '#u{width:1px;height:1px;padding:0;border:0}',
  },
  {
    name: 'offscreen-focus',
    source: 'script focuses an off-screen target so the menu opens without user intent',
    style: '#u{position:absolute;left:-9999px;top:0}',
    script: 'addEventListener("load",()=>{document.getElementById("u").focus()})',
  },
  {
    name: 'popover-before',
    source: 'DEF CON 33 popover API: a page popover is open before the menu would show',
    body: '<div id="pop" popover="manual" style="position:fixed;inset:0;margin:0;border:0;padding:0;background:transparent;width:100%;height:100%"></div>',
    script: 'addEventListener("load",()=>{document.getElementById("pop").showPopover()})',
  },
  {
    name: 'popover-after-show',
    source: 'DEF CON 33 popover API: a page popover opens above the menu after it is shown',
    body: '<div id="pop" popover="manual" style="position:fixed;inset:0;margin:0;border:0;padding:0;background:transparent;width:100%;height:100%"></div>',
    script: 'window.attack=()=>{document.getElementById("pop").showPopover()}',
  },
  {
    name: 'dialog-modal-after-show',
    source: 'a transparent modal dialog makes everything else inert after the menu is shown',
    body: '<dialog id="dlg" style="border:0;padding:0;background:transparent;width:100%;height:100%;max-width:none;max-height:none"></dialog><style>dialog::backdrop{background:transparent}</style>',
    script: 'window.attack=()=>{document.getElementById("dlg").showModal()}',
  },
  {
    name: 'overlay-over-target-after-show',
    source: 'an invisible element is placed over the target after the menu is shown',
    script:
      'window.attack=()=>{const r=document.getElementById("u").getBoundingClientRect();const d=document.createElement("div");d.style.cssText="position:fixed;z-index:9;background:rgba(0,0,0,.01);left:"+r.left+"px;top:"+r.top+"px;width:"+r.width+"px;height:"+r.height+"px";document.body.append(d)}',
  },
  {
    name: 'target-replaced-after-show',
    source: 'DOM move after fill start: the target is removed and a clone inserted',
    script:
      'window.attack=()=>{const u=document.getElementById("u");const c=u.cloneNode(true);u.replaceWith(c)}',
  },
  {
    name: 'class-toggle-after-show',
    source: 'a class change hides the target ancestor right before the click',
    style: '.hide{opacity:0}',
    script: 'window.attack=()=>{document.getElementById("f").classList.add("hide")}',
  },
  {
    name: 'zoom-root-after-show',
    source: 'zoom anomaly on html after the menu is shown',
    script: 'window.attack=()=>{document.documentElement.style.zoom="0.1"}',
  },
  {
    name: 'cursor-following-overlay',
    source:
      'DEF CON 33 overlay: an invisible element follows the cursor and covers the target, so the target counts as obscured',
    style:
      '#ov{position:fixed;width:200px;height:200px;background:rgba(0,0,0,.01);z-index:2147483646;pointer-events:auto}',
    body: '<div id="ov"></div>',
    script:
      'addEventListener("pointermove",(e)=>{const o=document.getElementById("ov");o.style.left=(e.clientX-100)+"px";o.style.top=(e.clientY-100)+"px"})',
  },
  {
    name: 'synthetic-events',
    source: 'the page dispatches untrusted focus and click events to open the menu',
    script:
      'addEventListener("load",()=>{const u=document.getElementById("u");u.dispatchEvent(new FocusEvent("focusin",{bubbles:true,composed:true}));u.dispatchEvent(new MouseEvent("click",{bubbles:true,composed:true}))})',
  },
  {
    name: 'port-spoof',
    source: 'the page posts forged port handovers to every frame after the menu is shown',
    script:
      'window.attack=()=>{for(let i=0;i<window.frames.length;i++){const ch=new MessageChannel();try{window.frames[i].postMessage({kind:"hasp-port",nonce:"AAAAAAAAAAAAAAAAAAAAAAAA"},"*",[ch.port2])}catch(e){}ch.port1.postMessage({kind:"picked",itemId:"item-1",action:"fill",token:"AAAAAAAAAAAAAAAAAAAAAAAA"})}}',
  },
  {
    name: 'hidden-duplicate-fields',
    source: 'hidden duplicate fields must stay empty after a fill',
    body: '<form style="display:none"><input id="hu" name="username"><input id="hp" name="password" type="password"></form>',
  },
  {
    name: 'fake-menu',
    source: 'the page draws a lookalike menu and the user clicks it',
    body: '<div id="fake" style="position:fixed;left:40px;top:260px;width:340px;height:48px;border:1px solid #888;background:#fff">mino01 (fake)</div>',
  },
];

const render = (t: Technique): string => {
  const inputAttrs = '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${t.name}</title><style>body{font:14px sans-serif;margin:40px}form{width:320px;max-width:100%}input{display:block;width:300px;max-width:100%;height:32px;margin:8px 0}${t.style ?? ''}</style></head><body>${form(inputAttrs, t.wrapStart ?? '', t.wrapEnd ?? '')}${t.body ?? ''}<script>${t.script ?? ''}</script></body></html>\n`;
};

export const buildRedTeam = (): void => {
  mkdirSync(pagesDir, { recursive: true });
  for (const t of techniques) writeFileSync(join(pagesDir, `${t.name}.html`), render(t));
};

if (process.argv[1] === fileURLToPath(import.meta.url)) buildRedTeam();
