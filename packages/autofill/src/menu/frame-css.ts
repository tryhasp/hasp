const text = (name: string): string =>
  `font:var(--type-${name}-weight) var(--type-${name}-size)/var(--type-${name}-line-height) var(--type-${name}-family)`;

// Why: 44 pt is Apple's minimum touch target; the design tokens have no touch size yet.
export const TOUCH_TARGET_PX = 44;

export const frameCss = (): string => `
*{box-sizing:border-box;margin:0;padding:0}
html,body{overflow:hidden;background:transparent;color:var(--color-inline-menu-text);color-scheme:light;${text('body')};word-break:keep-all;-webkit-font-smoothing:antialiased}
button{font:inherit;color:inherit;background:none;border:0;text-align:left;cursor:default;outline:0}
button:focus-visible{box-shadow:inset 0 0 0 var(--border-focus-ring) var(--color-accent)}
.menu{width:var(--size-menu-width);border:var(--border-hairline) solid var(--color-inline-menu-border);border-radius:var(--radius-menu);overflow:hidden;background:var(--color-inline-menu-background)}
.head{height:var(--size-menu-header-height);display:flex;align-items:center;gap:var(--space-s10);padding:0 var(--space-s12);background:var(--color-inline-menu-header);border-bottom:var(--border-hairline) solid var(--color-inline-menu-divider)}
.tag{display:inline-flex;align-items:center;gap:var(--space-s6);height:var(--size-control-height-compact);padding:0 var(--space-s10) 0 var(--space-s8);border:var(--border-hairline) solid var(--color-control-border);border-radius:var(--radius-tag);background:var(--color-group);${text('caption-strong')};white-space:nowrap;flex:none}
.tag svg{width:var(--size-icon-small);height:var(--size-icon-small);fill:currentColor}
.org{margin-left:auto;${text('origin')};white-space:nowrap;overflow:hidden}
.org .d{color:var(--color-inline-menu-text-secondary)}
.org b{${text('origin-strong')}}
.row{width:100%;height:var(--size-menu-row-height);display:flex;align-items:center;gap:var(--space-s10);padding:0 var(--space-s12)}
.row[aria-current="true"]{background:var(--color-inline-menu-selected-row)}
.row[aria-current="true"] .n{font-weight:var(--font-weight-semibold)}
.tile{width:var(--size-tile);height:var(--size-tile);border-radius:var(--radius-tile);display:grid;place-items:center;${text('tile-letter')};background:var(--color-inline-menu-tile);color:var(--color-inline-menu-tile-text);flex:none}
.row[aria-current="true"] .tile{background:var(--color-inline-menu-selected-tile);color:var(--color-inline-menu-selected-tile-text)}
.t{flex:1;min-width:0}
.n{${text('body-medium')};white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.s,.v{${text('caption')};color:var(--color-inline-menu-text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sepl{height:var(--border-hairline);background:var(--color-inline-menu-divider)}
.act{width:100%;height:var(--size-menu-action-height);display:flex;align-items:center;gap:var(--space-s10);padding:0 var(--space-s12)}
.act[aria-current="true"]{background:var(--color-inline-menu-selected-row)}
kbd{margin-left:auto;${text('caption')};min-width:var(--size-keycap-min-width);text-align:center;padding:0 var(--space-s6);border-radius:var(--radius-keycap);background:var(--color-inline-menu-keycap);color:var(--color-inline-menu-keycap-text);line-height:var(--size-keycap-line-height)}
.note{padding:var(--space-s12);${text('caption')};color:var(--color-inline-menu-text-secondary)}
.save{padding:var(--space-s12)}
.save h1{${text('body-strong')};margin-bottom:var(--space-s4)}
.save .u{color:var(--color-inline-menu-text-secondary);margin-bottom:var(--space-s12)}
.btns{display:flex;gap:var(--space-s8);margin-top:var(--space-s12)}
.btn{height:var(--size-control-height);padding:0 var(--space-s14);border-radius:var(--radius-control);${text('body-medium')};display:inline-flex;align-items:center;border:var(--border-hairline) solid var(--color-control-border)}
.btn.pri{background:var(--color-accent);color:var(--color-on-accent);border-color:var(--color-accent)}
@media (pointer:coarse){html,body{-webkit-tap-highlight-color:transparent;-webkit-touch-callout:none;-webkit-user-select:none;user-select:none}.row,.act{min-height:${TOUCH_TARGET_PX}px}.btn{min-height:${TOUCH_TARGET_PX}px}kbd{display:none}}
`;
