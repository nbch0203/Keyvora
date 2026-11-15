//! Autofill origin-matching contract (docs/CONTRACTS.md §4): look-alike domains, deceptive subdomains, IDN, schemes.

use keyvora_vault::origin::{match_level, parse_android_app, parse_page_url};
use keyvora_vault::MatchLevel::{self, *};

fn m(entry: &str, page: &str) -> MatchLevel {
    match_level(entry, page)
}

#[test]
fn exact_origin() {
    assert_eq!(m("https://github.com", "https://github.com/login"), Exact);
    assert_eq!(m("github.com", "https://github.com/"), Exact, "entry without scheme defaults to https");
    assert_eq!(m("https://GitHub.COM.", "https://github.com"), Exact, "case and trailing dot normalized");
    assert_eq!(m("https://github.com:443/x", "https://github.com/y"), Exact);
}

#[test]
fn same_site_requires_confirmation_level() {
    assert_eq!(m("https://accounts.google.com", "https://mail.google.com"), SameSite);
    assert_eq!(m("https://example.co.uk", "https://login.example.co.uk"), SameSite);
    assert_eq!(m("https://github.com", "https://github.com:8443"), SameSite, "different port is not exact");
}

#[test]
fn deceptive_domains_never_match() {
    assert_eq!(m("https://github.com", "https://github.com.evil.com"), None);
    assert_eq!(m("https://github.com", "https://evilgithub.com"), None);
    assert_eq!(m("https://github.com", "https://github.co"), None);
    assert_eq!(m("https://paypal.com", "https://paypa1.com"), None);
    assert_eq!(m("https://bank.com", "https://bank.com-secure-login.net"), None);
    assert_eq!(m("https://example.co.uk", "https://other.co.uk"), None, "public suffix is not a site");
}

#[test]
fn private_suffixes_are_separate_sites() {
    assert_eq!(m("https://alice.github.io", "https://mallory.github.io"), None);
    assert_eq!(m("https://app.herokuapp.com", "https://evil.herokuapp.com"), None);
    assert_eq!(m("https://alice.github.io", "https://alice.github.io/repo"), Exact);
}

#[test]
fn idn_homographs_do_not_match() {
    // Cyrillic 'а' (U+0430) in "pаypal.com"
    assert_eq!(m("https://paypal.com", "https://p\u{0430}ypal.com"), None);
    let o = parse_page_url("https://p\u{0430}ypal.com/").unwrap();
    assert!(o.host.starts_with("xn--"), "host shown as punycode: {}", o.host);
    assert!(o.is_idn());
    // the same IDN stored and visited matches
    assert_eq!(m("https://bücher.de", "https://xn--bcher-kva.de/"), Exact);
}

#[test]
fn schemes_and_insecure_pages() {
    assert_eq!(m("https://example.com", "http://example.com"), None, "plain http page never fillable");
    assert_eq!(m("http://example.com", "http://example.com"), None, "even if stored as http");
    assert_eq!(m("http://localhost:3000", "http://localhost:3000/login"), Exact, "loopback is a secure context");
    assert_eq!(m("http://127.0.0.1:8080", "http://127.0.0.1:8080"), Exact);
    for page in [
        "file:///etc/passwd",
        "data:text/html,<form>",
        "javascript:alert(1)",
        "chrome-extension://abc/popup.html",
        "ftp://example.com",
        "about:blank",
        "",
    ] {
        assert_eq!(m("https://example.com", page), None, "{page}");
    }
}

#[test]
fn ip_addresses_exact_only() {
    assert_eq!(m("https://192.168.1.10", "https://192.168.1.10/admin"), Exact);
    assert_eq!(m("https://192.168.1.10", "https://192.168.1.11"), None);
    assert_eq!(m("https://[2001:db8::1]", "https://[2001:db8::1]:443/"), Exact);
}

#[test]
fn credentials_in_entry_url_rejected() {
    assert_eq!(m("https://user:pass@example.com", "https://example.com"), None);
}

#[test]
fn android_packages() {
    assert_eq!(parse_android_app("androidapp://com.example.app").as_deref(), Some("com.example.app"));
    assert_eq!(parse_android_app("androidapp://com.example.app/").as_deref(), Some("com.example.app"));
    for bad in
        ["androidapp://", "androidapp://noperiod", "androidapp://com..x", "androidapp://1com.x", "https://com.example"]
    {
        assert!(parse_android_app(bad).is_none(), "{bad}");
    }
}
