import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

type Gold = { forms: { selector: string; kind: string; fields: Record<string, string> }[] };
type Page = { name: string; lang: string; title: string; body: string; gold: Gold; path?: string };

const here = dirname(fileURLToPath(import.meta.url));
const pagesDir = join(here, 'pages');

const userVariants: { html: string; ko: boolean }[] = [
  {
    html: '<label for="u">Username</label><input id="u" name="username" autocomplete="username" data-c="u">',
    ko: false,
  },
  { html: '<input type="email" name="email" placeholder="Email address" data-c="u">', ko: false },
  { html: '<label>아이디 <input name="id" data-c="u"></label>', ko: true },
  { html: '<input name="loginId" placeholder="아이디 입력" data-c="u">', ko: true },
  { html: '<input name="uid" aria-label="User ID" data-c="u">', ko: false },
  { html: '<input name="txtUserID" type="text" data-c="u">', ko: false },
  {
    html: '<table><tr><td>아이디</td><td><input type="text" name="a1" data-c="u"></td></tr></table>',
    ko: true,
  },
  { html: '<input type="text" data-c="u">', ko: false },
  { html: '<input name="member_id" placeholder="회원번호 또는 이메일" data-c="u">', ko: true },
  { html: '<input type="tel" name="phone" autocomplete="username" data-c="u">', ko: false },
];

const passVariants: string[] = [
  '<input type="password" name="password" autocomplete="current-password" data-c="p">',
  '<input type="password" name="pw" data-c="p">',
  '<input type="text" name="passwd" style="-webkit-text-security:disc" data-c="p">',
  '<input type="password" placeholder="비밀번호" data-c="p">',
  '<input type="text" name="userpw" class="mask" data-c="p"><style>.mask{-webkit-text-security:disc}</style>',
  '<input type="password" name="pwd" readonly placeholder="비밀번호 (키보드 보안)" data-c="p">',
  '<label>비밀번호 <input type="password" data-c="p"></label>',
  '<input type="password" aria-label="Password" data-c="p">',
];

const wrap = (inner: string, style: number, submit: string): string => {
  if (style === 0)
    return `<form method="post" data-k="login">${inner}<button type="submit">${submit}</button></form>`;
  if (style === 1)
    return `<main><div class="box" data-k="login">${inner}<button type="button">${submit}</button></div></main>`;
  return `<div role="dialog" aria-label="auth" data-k="login">${inner}<div><input type="checkbox" id="r"><label for="r">Remember me</label></div><button>${submit}</button></div>`;
};

const distractors = [
  '',
  '<header><input type="search" name="q" placeholder="검색"></header>',
  '<div style="display:none"><input type="text" name="email"></div>',
  '<header><input type="text" name="q" placeholder="Search products"></header>',
];

const pages: Page[] = [];
const add = (p: Page): void => {
  pages.push(p);
};

let seq = 0;
for (const [i, u] of userVariants.entries()) {
  for (const [j, p] of passVariants.entries()) {
    seq += 1;
    if ((i + j) % 3 !== seq % 3) continue;
    const style = seq % 3;
    const submit = u.ko ? '로그인' : 'Sign in';
    const hasPositional =
      u.html.includes('data-c="u"') &&
      !/name=|id=|aria|placeholder|<td|label|autocomplete/.test(u.html);
    add({
      name: `login-${String(seq).padStart(3, '0')}`,
      lang: u.ko ? 'ko' : 'en',
      title: submit,
      body: `${distractors[seq % distractors.length] ?? ''}${wrap(`${u.html}${p}`, style, submit)}`,
      gold: {
        forms: [
          {
            selector: '[data-k="login"]',
            kind: 'login',
            fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
          },
        ],
      },
    });
    void hasPositional;
  }
}

for (const [i, u] of userVariants.slice(0, 6).entries()) {
  add({
    name: `username-only-${String(i + 1).padStart(2, '0')}`,
    lang: u.ko ? 'ko' : 'en',
    title: 'step 1',
    body: `<form data-k="username-only">${u.html}<button type="submit">${u.ko ? '다음' : 'Continue'}</button></form>`,
    gold: {
      forms: [
        {
          selector: '[data-k="username-only"]',
          kind: 'username-only',
          fields: { '[data-c="u"]': 'username' },
        },
      ],
    },
  });
}
for (const [i, p] of passVariants.slice(0, 6).entries()) {
  add({
    name: `password-only-${String(i + 1).padStart(2, '0')}`,
    lang: 'en',
    title: 'step 2',
    body: `<form data-k="password-only"><p>Welcome back</p>${p}<button type="submit">Sign in</button></form>`,
    gold: {
      forms: [
        {
          selector: '[data-k="password-only"]',
          kind: 'password-only',
          fields: { '[data-c="p"]': 'password' },
        },
      ],
    },
  });
}

const otpSingles = [
  '<input name="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" data-c="o">',
  '<label>인증번호 <input name="code" maxlength="6" data-c="o"></label>',
  '<input name="verification_code" placeholder="6-digit code" data-c="o">',
  '<input name="totp" placeholder="Authenticator code" inputmode="numeric" data-c="o">',
  '<input type="text" name="smsAuth" placeholder="인증 코드 6자리" data-c="o">',
  '<input name="token" autocomplete="one-time-code" data-c="o">',
];
for (const [i, o] of otpSingles.entries()) {
  add({
    name: `otp-${String(i + 1).padStart(2, '0')}`,
    lang: i % 2 === 1 ? 'ko' : 'en',
    title: '2FA',
    body: `<form data-k="otp"><h1>Two-factor authentication</h1>${o}<button type="submit">Verify</button></form>`,
    gold: {
      forms: [{ selector: '[data-k="otp"]', kind: 'otp', fields: { '[data-c="o"]': 'otp' } }],
    },
  });
}

const cells = (n: number, extra: string): string =>
  Array.from(
    { length: n },
    (_, k) =>
      `<input class="cell" maxlength="1" inputmode="numeric" ${extra} data-cell="${k}" style="width:40px;height:48px;margin-right:8px;text-align:center">`,
  ).join('');
for (const n of [4, 5, 6, 8]) {
  add({
    name: `otp-split-${n}`,
    lang: 'en',
    title: 'code',
    body: `<form data-k="otp-split"><p>Enter the ${n}-digit code</p><div style="display:flex">${cells(n, '')}</div><button type="submit">Verify</button></form>`,
    gold: {
      forms: [
        {
          selector: '[data-k="otp-split"]',
          kind: 'otp-split',
          fields: Object.fromEntries(
            Array.from({ length: n }, (_, k) => [`[data-cell="${k}"]`, 'otp-cell']),
          ),
        },
      ],
    },
  });
}
add({
  name: 'otp-split-ko-narrow',
  lang: 'ko',
  title: '인증',
  body: `<form data-k="otp-split"><p>인증번호 6자리를 입력해 주세요</p><div style="display:flex">${Array.from({ length: 6 }, (_, k) => `<input type="tel" data-cell="${k}" style="width:36px;height:44px;margin-right:6px">`).join('')}</div><button>확인</button></form>`,
  gold: {
    forms: [
      {
        selector: '[data-k="otp-split"]',
        kind: 'otp-split',
        fields: Object.fromEntries(
          Array.from({ length: 6 }, (_, k) => [`[data-cell="${k}"]`, 'otp-cell']),
        ),
      },
    ],
  },
});

const signupForms: string[] = [
  '<input name="email" type="email" autocomplete="email" data-c="e"><input type="password" name="password" autocomplete="new-password" data-c="n"><input type="password" name="confirm" placeholder="Confirm password" data-c="c">',
  '<input name="username" data-c="e"><input type="password" name="pw" autocomplete="new-password" data-c="n">',
  '<label>아이디 <input name="userId" data-c="e"></label><label>비밀번호 <input type="password" name="pw1" data-c="n"></label><label>비밀번호 확인 <input type="password" name="pw2" data-c="c"></label>',
  '<input name="name" placeholder="Full name"><input name="email" type="email" data-c="e"><input type="password" name="password" data-c="n"><input type="password" name="password2" placeholder="Re-enter password" data-c="c">',
  '<input name="email" type="email" data-c="e"><input type="password" placeholder="Create a password" data-c="n">',
  '<input type="text" name="phone"><input type="password" name="newPassword" data-c="n"><input type="password" name="newPasswordConfirm" data-c="c">',
];
for (const [i, s] of signupForms.entries()) {
  const ko = s.includes('아이디');
  add({
    name: `signup-${String(i + 1).padStart(2, '0')}`,
    lang: ko ? 'ko' : 'en',
    title: 'join',
    path: '/signup',
    body: `<form data-k="signup"><h1>${ko ? '회원가입' : 'Create account'}</h1>${s}<button type="submit">${ko ? '가입하기' : 'Sign up'}</button></form>`,
    gold: {
      forms: [
        {
          selector: '[data-k="signup"]',
          kind: 'signup',
          fields: { '[data-c="n"]': 'new-password' },
        },
      ],
    },
  });
}

const changeForms: string[] = [
  '<input type="password" name="current" autocomplete="current-password" data-c="o"><input type="password" name="new" autocomplete="new-password" data-c="n"><input type="password" name="confirm" placeholder="Confirm new password" data-c="c">',
  '<label>현재 비밀번호 <input type="password" name="a" data-c="o"></label><label>새 비밀번호 <input type="password" name="b" data-c="n"></label><label>새 비밀번호 확인 <input type="password" name="c" data-c="c"></label>',
  '<input type="password" name="oldPassword" placeholder="Old password" data-c="o"><input type="password" name="newPassword" data-c="n"><input type="password" name="newPassword2" placeholder="Retype new password" data-c="c">',
];
for (const [i, s] of changeForms.entries()) {
  add({
    name: `change-password-${String(i + 1).padStart(2, '0')}`,
    lang: i === 1 ? 'ko' : 'en',
    title: 'change',
    body: `<form data-k="change-password">${s}<button type="submit">Change password</button></form>`,
    gold: {
      forms: [
        {
          selector: '[data-k="change-password"]',
          kind: 'change-password',
          fields: { '[data-c="o"]': 'current-password', '[data-c="n"]': 'new-password' },
        },
      ],
    },
  });
}

const cards: string[] = [
  '<input name="cardnumber" autocomplete="cc-number" data-c="n"><input name="exp" autocomplete="cc-exp" data-c="e"><input name="cvc" autocomplete="cc-csc" data-c="s">',
  '<label>카드번호 <input name="cn" data-c="n"></label><label>유효기간 <input name="ex" placeholder="MM/YY" data-c="e"></label><label>CVC <input name="cv" data-c="s"></label>',
  '<input name="card_number" placeholder="Card number" data-c="n"><select name="m" autocomplete="cc-exp-month" data-c="m"><option value="01">01</option></select><select name="y" autocomplete="cc-exp-year" data-c="y"><option value="2029">2029</option></select><input name="cvv" data-c="s">',
];
for (const [i, c] of cards.entries()) {
  const base: Record<string, string> = { '[data-c="n"]': 'cc-number' };
  if (c.includes('data-c="s"')) base['[data-c="s"]'] = 'cc-csc';
  if (c.includes('data-c="e"')) base['[data-c="e"]'] = 'cc-exp';
  if (c.includes('data-c="m"')) base['[data-c="m"]'] = 'cc-exp-month';
  if (c.includes('data-c="y"')) base['[data-c="y"]'] = 'cc-exp-year';
  add({
    name: `card-${String(i + 1).padStart(2, '0')}`,
    lang: i === 1 ? 'ko' : 'en',
    title: 'pay',
    body: `<form data-k="card"><h1>Payment</h1>${c}<button>Pay</button></form>`,
    gold: { forms: [{ selector: '[data-k="card"]', kind: 'card', fields: base }] },
  });
}
add({
  name: 'card-split-4',
  lang: 'ko',
  title: '카드',
  body:
    '<form data-k="card"><label>카드번호</label><div style="display:flex">' +
    Array.from(
      { length: 4 },
      (_, k) =>
        `<input maxlength="4" inputmode="numeric" data-part="${k}" style="width:70px;margin-right:6px">`,
    ).join('') +
    '</div><input name="cvc" placeholder="CVC" data-c="s"></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="card"]',
        kind: 'card',
        fields: {
          '[data-part="0"]': 'cc-number-part',
          '[data-part="1"]': 'cc-number-part',
          '[data-part="2"]': 'cc-number-part',
          '[data-part="3"]': 'cc-number-part',
          '[data-c="s"]': 'cc-csc',
        },
      },
    ],
  },
});

const none = (name: string, body: string, lang = 'en'): void => {
  add({ name: `none-${name}`, lang, title: name, body, gold: { forms: [] } });
};
none(
  'search',
  '<form role="search"><input type="search" name="q" placeholder="Search"><button>Go</button></form>',
);
none(
  'search-ko',
  '<form><input type="text" name="keyword" placeholder="검색어를 입력하세요"><button>검색</button></form>',
  'ko',
);
none(
  'newsletter',
  '<form><input type="email" name="email" placeholder="you@example.com"><button>Subscribe</button></form>',
);
none(
  'newsletter-ko',
  '<form><input type="email" name="subscribeEmail" placeholder="이메일 주소"><button>뉴스레터 구독</button></form>',
  'ko',
);
none(
  'coupon',
  '<form><input name="coupon" placeholder="Coupon code"><button>Apply</button></form>',
);
none(
  'coupon-ko',
  '<form><input name="couponNo" placeholder="쿠폰 번호"><button>등록</button></form>',
  'ko',
);
none('chat', '<div><textarea name="message"></textarea><button>Send</button></div>');
none(
  'captcha',
  '<form><input name="captcha" placeholder="Type the characters"><button>Verify</button></form>',
);
none(
  'captcha-ko',
  '<form><input name="captchaAnswer" placeholder="자동입력 방지문자"><button>확인</button></form>',
  'ko',
);
none('empty', '<p>Nothing to see</p>');
none(
  'comment',
  '<form><input name="author"><textarea name="comment"></textarea><button>Post</button></form>',
);
none(
  'referral',
  '<form><input name="referral" placeholder="추천인 코드"><button>확인</button></form>',
  'ko',
);
none(
  'hidden-login',
  '<form style="display:none"><input name="username"><input type="password" name="password"></form><p>Maintenance</p>',
);
none(
  'disabled-login',
  '<form><input name="username" disabled><input type="password" name="password" disabled></form>',
);
none(
  'quantity',
  '<form><input type="number" name="qty" value="1"><button>Add to cart</button></form>',
);
none(
  'date',
  '<form><input type="text" name="birthdate" placeholder="YYYY-MM-DD"><button>Save</button></form>',
);
none(
  'zeroSize',
  '<form><input name="username" style="width:0;height:0;padding:0;border:0"><input type="password" style="width:0;height:0;padding:0;border:0"></form>',
);

none(
  'contact',
  '<form><input name="name"><input type="email" name="email"><textarea name="message"></textarea><button>Send message</button></form>',
);
none(
  'profile-settings',
  '<form><input name="displayName" placeholder="Display name"><input name="website" type="url"><textarea name="bio"></textarea><button>Save</button></form>',
);
none(
  'admin-user-lookup',
  '<form><input name="userId" placeholder="Enter user ID to look up"><button>Go</button></form>',
);
none(
  'pin-cells',
  '<form><p>Enter your 4-digit PIN</p><div style="display:flex">' +
    Array.from(
      { length: 4 },
      () =>
        '<input type="password" maxlength="1" inputmode="numeric" style="width:40px;margin-right:6px">',
    ).join('') +
    '</div><button>Unlock</button></form>',
);
none(
  'account-number',
  '<form><input name="accountNumber" placeholder="Account number"><button>Check balance</button></form>',
);
none(
  'invite-code',
  '<form><input name="invite" placeholder="Invite code"><button>Continue</button></form>',
);
none(
  'terms-only',
  '<form><label><input type="checkbox"> I agree</label><button>Continue</button></form>',
);
none(
  'quantity-select',
  '<form><select name="size"><option>S</option></select><button>Add</button></form>',
);
add({
  name: 'login-id-placeholders',
  lang: 'en',
  title: 'in',
  body: '<form data-k="login"><input placeholder="ID" data-c="u"><input type="password" placeholder="PW" data-c="p"><button>Log in</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'login-naver-like',
  lang: 'ko',
  title: '로그인',
  body: '<form data-k="login"><input id="id" name="id" placeholder="아이디" maxlength="41" data-c="u"><input type="password" id="pw" name="pw" placeholder="비밀번호" maxlength="16" data-c="p"><input type="hidden" name="enctp" value="1"><input type="hidden" name="nkey"><button class="btn_login">로그인</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'login-kakao-like',
  lang: 'ko',
  title: '로그인',
  body: '<form data-k="login"><input name="loginId" placeholder="카카오계정(이메일 또는 전화번호)" data-c="u"><input type="password" name="password" placeholder="비밀번호" data-c="p"><button>로그인</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'login-with-captcha-field',
  lang: 'en',
  title: 'in',
  body: '<form data-k="login"><input name="username" data-c="u"><input type="password" name="password" data-c="p"><input name="captcha" placeholder="Type the text" data-x="1"><button>Sign in</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'login-company-code',
  lang: 'en',
  title: 'in',
  body: '<form data-k="login"><input name="companyCode" placeholder="Company code"><input name="userId" placeholder="User ID" data-c="u"><input type="password" name="password" data-c="p"><button>Sign in</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'login-path-hint',
  lang: 'en',
  title: 'in',
  path: '/login',
  body: '<form data-k="login"><input data-c="u"><input type="password" data-c="p"><button>Go</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="login"]',
        kind: 'login',
        fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
      },
    ],
  },
});
add({
  name: 'username-only-lookup-hint',
  lang: 'en',
  title: 'in',
  path: '/login',
  body: '<form data-k="username-only"><input name="identifier" autocomplete="username webauthn" data-c="u"><button>Next</button></form>',
  gold: {
    forms: [
      {
        selector: '[data-k="username-only"]',
        kind: 'username-only',
        fields: { '[data-c="u"]': 'username' },
      },
    ],
  },
});

const identity = (
  name: string,
  html: string,
  kind: string,
  fields: Record<string, string>,
  lang = 'en',
): void => {
  add({
    name: `${kind}-${name}`,
    lang,
    title: name,
    body: `<form data-k="${kind}">${html}<button>Save</button></form>`,
    gold: { forms: [{ selector: `[data-k="${kind}"]`, kind, fields }] },
  });
};
identity(
  'basic',
  '<input name="fname" autocomplete="given-name" data-c="g"><input name="lname" autocomplete="family-name" data-c="f"><input name="email" type="email" autocomplete="email" data-c="e"><input type="tel" name="phone" autocomplete="tel" data-c="t">',
  'identity',
  { '[data-c="g"]': 'given-name', '[data-c="f"]': 'family-name', '[data-c="t"]': 'tel' },
);
identity(
  'ko',
  '<label>이름 <input name="nm" data-c="n"></label><label>휴대폰 번호 <input name="hp" data-c="t"></label>',
  'identity',
  { '[data-c="n"]': 'name', '[data-c="t"]': 'tel' },
  'ko',
);
identity(
  'basic',
  '<input name="street" autocomplete="street-address" data-c="s"><input name="zip" autocomplete="postal-code" data-c="z"><select name="country" autocomplete="country" data-c="c"><option value="KR">Korea</option></select>',
  'address',
  { '[data-c="s"]': 'street-address', '[data-c="z"]': 'postal-code', '[data-c="c"]': 'country' },
);
identity(
  'ko',
  '<label>우편번호 <input name="zipcode" data-c="z"></label><label>상세주소 <input name="addr2" data-c="a"></label>',
  'address',
  { '[data-c="z"]': 'postal-code', '[data-c="a"]': 'address-line2' },
  'ko',
);

const koreanSpecial: Page[] = [
  {
    name: 'ko-bank-virtual-keypad',
    lang: 'ko',
    title: '하늘은행 로그인',
    body: '<div class="wrap" data-k="login"><label>아이디<input type="text" name="userId" data-c="u"></label><label>비밀번호<input type="password" name="pwdInput" readonly placeholder="비밀번호 (마우스 입력)" data-c="p"></label><div class="kp"><button type="button">1</button><button type="button">2</button><button type="button">3</button></div><button type="button">로그인</button></div>',
    gold: {
      forms: [
        {
          selector: '[data-k="login"]',
          kind: 'login',
          fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
        },
      ],
    },
  },
  {
    name: 'ko-masked-text-password',
    lang: 'ko',
    title: '로그인',
    body: '<style>.sec{-webkit-text-security:disc}</style><form data-k="login"><input type="text" name="mb_id" placeholder="아이디" data-c="u"><input type="text" name="mb_pw" class="sec" placeholder="비밀번호" data-c="p"><button type="submit">로그인</button></form>',
    gold: {
      forms: [
        {
          selector: '[data-k="login"]',
          kind: 'login',
          fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
        },
      ],
    },
  },
  {
    name: 'ko-portal-tabs',
    lang: 'ko',
    title: '통합 로그인',
    body: '<ul><li>ID 로그인</li><li>QR 로그인</li></ul><form data-k="login"><input id="id" name="id" title="아이디" placeholder="아이디" data-c="u"><input id="pw" name="pw" type="password" title="비밀번호" placeholder="비밀번호" data-c="p"><label><input type="checkbox"> 로그인 상태 유지</label><button type="submit" class="btn_login">로그인</button></form>',
    gold: {
      forms: [
        {
          selector: '[data-k="login"]',
          kind: 'login',
          fields: { '[data-c="u"]': 'username', '[data-c="p"]': 'password' },
        },
      ],
    },
  },
  {
    name: 'ko-signup-id-pw',
    lang: 'ko',
    title: '회원가입',
    path: '/join',
    body: '<form data-k="signup"><h1>회원가입</h1><label>아이디 <input name="id"></label><label>비밀번호 <input type="password" name="pw" data-c="n"></label><label>비밀번호 재확인 <input type="password" name="pw2" data-c="c"></label><label>이름 <input name="name"></label><label>휴대전화 <input name="tel"></label><button>가입하기</button></form>',
    gold: {
      forms: [
        {
          selector: '[data-k="signup"]',
          kind: 'signup',
          fields: { '[data-c="n"]': 'new-password' },
        },
      ],
    },
  },
  {
    name: 'ko-sms-otp-with-timer',
    lang: 'ko',
    title: '본인확인',
    body: '<form data-k="otp"><p>문자로 받은 인증번호를 입력해 주세요 <span>02:59</span></p><input name="authNo" maxlength="6" placeholder="인증번호 6자리" data-c="o"><button>확인</button></form>',
    gold: {
      forms: [{ selector: '[data-k="otp"]', kind: 'otp', fields: { '[data-c="o"]': 'otp' } }],
    },
  },
  {
    name: 'ko-sso-step-1',
    lang: 'ko',
    title: '로그인',
    body: '<form data-k="username-only"><label>이메일 또는 전화번호<input name="loginKey" autocomplete="username" data-c="u"></label><button type="submit">다음</button></form>',
    gold: {
      forms: [
        {
          selector: '[data-k="username-only"]',
          kind: 'username-only',
          fields: { '[data-c="u"]': 'username' },
        },
      ],
    },
  },
];
for (const p of koreanSpecial) add(p);

export const buildCorpus = (): void => {
  rmSync(pagesDir, { recursive: true, force: true });
  mkdirSync(pagesDir, { recursive: true });
  const golden: Record<string, Gold & { path: string; lang: string }> = {};
  for (const p of pages) {
    const html = `<!doctype html><html lang="${p.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${p.title}</title></head><body>${p.body}</body></html>\n`;
    writeFileSync(join(pagesDir, `${p.name}.html`), html);
    golden[p.name] = { ...p.gold, path: p.path ?? '', lang: p.lang };
  }
  writeFileSync(join(here, 'golden.json'), `${JSON.stringify(golden, null, 2)}\n`);
};

buildCorpus();
