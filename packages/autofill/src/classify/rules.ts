import type { FieldPurpose } from '../types.ts';

export type TextRule = { purpose: FieldPurpose; pattern: RegExp; weight: number };

export const AUTOCOMPLETE_WEIGHT = 12;
export const TYPE_WEIGHT = 8;
export const NEARBY_FACTOR = 1;

export const autocompletePurposes: Readonly<Record<string, FieldPurpose>> = {
  username: 'username',
  email: 'email',
  'current-password': 'current-password',
  'new-password': 'new-password',
  'one-time-code': 'otp',
  'cc-number': 'cc-number',
  'cc-exp': 'cc-exp',
  'cc-exp-month': 'cc-exp-month',
  'cc-exp-year': 'cc-exp-year',
  'cc-csc': 'cc-csc',
  'cc-name': 'cc-name',
  'cc-type': 'cc-type',
  name: 'name',
  'given-name': 'given-name',
  'family-name': 'family-name',
  tel: 'tel',
  'tel-national': 'tel',
  'street-address': 'street-address',
  'address-line1': 'address-line1',
  'address-line2': 'address-line2',
  'postal-code': 'postal-code',
  country: 'country',
  'country-name': 'country',
};

export const textRules: readonly TextRule[] = [
  {
    purpose: 'none',
    pattern:
      /captcha|recaptcha|자동 ?입력 ?방지|보안 ?문자|search|검색|coupon|promo|referr|추천인|쿠폰|newsletter|구독/,
    weight: 14,
  },
  {
    purpose: 'username',
    pattern:
      /user ?name|user ?id|login ?id|member ?id|sign ?in ?id|account ?id|(^|[^a-z])(uid|usr|id|login|account|member)([^a-z]|$)|아이디|계정|회원 ?번호|사용자/,
    weight: 5,
  },
  { purpose: 'email', pattern: /e ?-?mail|이메일|메일 ?주소/, weight: 5 },
  {
    purpose: 'password',
    pattern: /pass ?word|passwd|pwd|passcode|비밀 ?번호|비번|패스워드|암호/,
    weight: 6,
  },
  {
    purpose: 'new-password',
    pattern:
      /new ?pass|새 ?비밀 ?번호|신규 ?비밀 ?번호|새로운 ?비밀 ?번호|create ?password|choose ?a? ?password/,
    weight: 7,
  },
  {
    purpose: 'current-password',
    pattern:
      /current ?pass|old ?pass|existing ?pass|현재 ?비밀 ?번호|기존 ?비밀 ?번호|이전 ?비밀 ?번호/,
    weight: 7,
  },
  {
    purpose: 'confirm-password',
    pattern:
      /confirm ?(new ?)?pass|retype|re ?-?enter ?pass|repeat ?pass|verify ?pass|비밀 ?번호 ?(재 ?입력|확인)|비밀 ?번호 ?한 ?번 ?더|확인 ?용 ?비밀 ?번호|pass(word)? ?(2|confirm|check)/,
    weight: 9,
  },
  {
    purpose: 'otp',
    pattern:
      /one ?-?time|otp|2 ?fa|two ?-?factor|verification ?code|auth(enticator)? ?code|security ?code|sms ?code|인증 ?번호|인증 ?코드|보안 ?코드|일회용|확인 ?코드|인증 ?문자|6 ?자리|6 ?digit/,
    weight: 6,
  },
  {
    purpose: 'cc-number',
    pattern: /card ?(number|no)|cc ?-?num|카드 ?번호|신용 ?카드 ?번호|카드번호/,
    weight: 7,
  },
  {
    purpose: 'cc-csc',
    pattern: /cvc|cvv|csc|security ?code ?\(?card|보안 ?코드 ?\(?카드|카드 ?뒷면/,
    weight: 8,
  },
  { purpose: 'cc-exp', pattern: /expir|exp ?date|valid ?(thru|until)|유효 ?기간|만료/, weight: 6 },
  {
    purpose: 'cc-exp-month',
    pattern: /exp(iry|iration)? ?-?month|(^|[^a-z])mm([^a-z]|$)|유효 ?기간 ?월|^월$/,
    weight: 7,
  },
  {
    purpose: 'cc-exp-year',
    pattern: /exp(iry|iration)? ?-?year|(^|[^a-z])yy(yy)?([^a-z]|$)|유효 ?기간 ?년|^년$/,
    weight: 7,
  },
  {
    purpose: 'cc-name',
    pattern: /name ?on ?card|card ?holder|카드 ?소유자|카드 ?명의|명의자/,
    weight: 8,
  },
  { purpose: 'given-name', pattern: /first ?-?name|given ?-?name|fname|^이름$/, weight: 6 },
  { purpose: 'family-name', pattern: /last ?-?name|family ?-?name|surname|lname|^성$/, weight: 6 },
  {
    purpose: 'name',
    pattern: /full ?-?name|(^|[^a-z])name([^a-z]|$)|성명|이름|실명|예금주/,
    weight: 4,
  },
  {
    purpose: 'tel',
    pattern:
      /phone|mobile|(^|[^a-z])tel([^a-z]|$)|휴대 ?폰|휴대 ?전화|핸드폰|전화 ?번호|연락처|휴대전화/,
    weight: 6,
  },
  { purpose: 'postal-code', pattern: /zip|postal|post ?code|우편 ?번호|우편번호/, weight: 7 },
  {
    purpose: 'address-line2',
    pattern: /address ?(line ?)?2|apt|suite|상세 ?주소|나머지 ?주소/,
    weight: 7,
  },
  { purpose: 'address-line1', pattern: /address ?(line ?)?1|street|도로명|지번|주소/, weight: 5 },
  { purpose: 'country', pattern: /country|nation|국가|나라/, weight: 6 },
];

export const submitLogin = /log ?-?in|sign ?-?in|로그인|접속|입장|log ?on/;
export const submitContinue = /next|continue|다음|계속|확인/;
export const submitSignup =
  /sign ?-?up|register|join|create ?(an )?account|get started|회원 ?가입|가입(하기|완료)?|계정 ?만들기/;
export const submitChange =
  /change ?pass|update ?pass|reset|비밀 ?번호 ?(변경|재설정|바꾸기)|변경하기/;
export const submitSubscribe = /subscribe|구독|뉴스레터/;

export const pathSignup =
  /(^|[/_-])(sign ?up|signup|register|registration|join|create-account|회원가입|가입)([/_.-]|$)/;
export const pathLogin = /(^|[/_-])(log ?-?in|sign ?-?in|signin|auth|sso|session|로그인)([/_.-]|$)/;
export const pathChange =
  /(change|update|reset|forgot)[-_]?pass|passwd|비밀번호변경|password\/(change|reset)/;

export const errorText =
  /incorrect|invalid (username|password|credentials)|wrong (password|credentials)|try again|failed|일치하지 않|올바르지 않|잘못|실패|오류|확인해 주세요/;
