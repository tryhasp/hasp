pub const HOST_NAME: &str = "kr.jmo.hasp.nmh";
pub const HOST_DESCRIPTION: &str = "Hasp desktop bridge";
pub const HOST_IDENTIFIER: &str = "kr.jmo.hasp.nmh";
pub const APP_GROUP_SUFFIX: &str = "kr.jmo.hasp";
pub const SOCKET_NAME: &str = "nmh.sock";

pub const CHROMIUM_STORE_IDS: &[&str] = &[];
pub const FIREFOX_STORE_IDS: &[&str] = &[];

pub const CHROMIUM_DEV_ID: &str = "gchilemfcapcihefglfdhgihpcjcdogp";
pub const FIREFOX_DEV_ID: &str = "hasp-dev@hasp.app";
pub const CHROMIUM_DEV_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsU1pob4VpPcskhLoYai5nMXGug3+/wNUbCCE6Wzicywvs2uouyQDvjh+FYr5buDpM/qKs+1fQS1rWULcy3is2CEWA556SjVXoI933jCz/cCfxcDKmJbADxzKKzC8TCEPlSzAoPlqVLvGFGlFTWDdXTYeomQ3T3vjXjkcklB3391ut1qpY6BvcY1Dwzroopo4ZQNWPmBylwek7s2JYat5G5KoXKvVXzANaHNer36hnIxWGnBjfgz25p4OKoZsN32yXPrm+wRpPWu8c/I/cQay9bA74w8EC8cA5jeUvpYTtEoeULNtNbz4BvUGQvsCuKu6YIrpDXBz5lUaOJ569TuE4wIDAQAB";

pub const TEAM_ID: Option<&str> = option_env!("HASP_TEAM_ID");
pub const APP_IDENTIFIER: &str = "kr.jmo.hasp";

#[cfg(feature = "dev-extension")]
pub const DEV_BUILD_MARKER: &str = "hasp-nmh-dev-extension-build";
