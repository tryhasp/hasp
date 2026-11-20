export const locales = ['ko', 'en'] as const;
export type Locale = (typeof locales)[number];

export type Strings = {
  menuLabel: string;
  tagTitle: string;
  generate: string;
  fillOnHost: (host: string) => string;
  relatedSite: string;
  fillOtp: string;
  empty: string;
  blocked: string;
  saveNew: string;
  saveUpdate: string;
  save: string;
  update: string;
  notNow: string;
  never: string;
  strikeNotice: string;
  fillRefused: string;
  copyHint: string;
};

export const strings: Record<Locale, Strings> = {
  ko: {
    menuLabel: 'Hasp',
    tagTitle: '내 표시',
    generate: '새 비밀번호 생성',
    fillOnHost: (host) => `${host}에서 채우기`,
    relatedSite: '관련 사이트',
    fillOtp: '인증 코드 채우기',
    empty: '이 사이트에 저장된 항목이 없어요',
    blocked: '이 사이트는 자동 채우기를 막아요. 비밀번호를 복사해 주세요.',
    saveNew: '이 로그인을 저장할까요?',
    saveUpdate: '저장된 비밀번호를 바꿀까요?',
    save: '저장',
    update: '바꾸기',
    notNow: '나중에',
    never: '이 사이트에서는 저장 안 함',
    strikeNotice: '이 페이지에서는 메뉴를 끌게요. 페이지가 메뉴를 가리려고 했어요.',
    fillRefused: '채우지 못했어요. 직접 입력하거나 복사해 주세요.',
    copyHint: '복사',
  },
  en: {
    menuLabel: 'Hasp',
    tagTitle: 'Your mark',
    generate: 'Generate new password',
    fillOnHost: (host) => `Fill on ${host}`,
    relatedSite: 'Related site',
    fillOtp: 'Fill one-time code',
    empty: 'Nothing saved for this site',
    blocked: 'This site blocks autofill. Copy the password instead.',
    saveNew: 'Save this login?',
    saveUpdate: 'Update the saved password?',
    save: 'Save',
    update: 'Update',
    notNow: 'Not now',
    never: 'Never for this site',
    strikeNotice: 'The menu is off on this page. The page tried to cover it.',
    fillRefused: 'Could not fill. Type it or copy it.',
    copyHint: 'Copy',
  },
};
