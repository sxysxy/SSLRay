//! Read-only Windows trust anchors for OpenSSL. No network or store mutation.
//! This imports eligible ROOT certificates, not MY/CA or peer certificates.
//! It does not implement the complete Windows chain engine or online revocation.
use anyhow::{Context, Result, ensure};
use openssl::{ssl::SslConnectorBuilder, x509::X509};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io,
    mem::size_of,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CRYPT_E_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, SetLastError,
    },
    Security::Cryptography::{
        CERT_BASIC_CONSTRAINTS2_INFO, CERT_CONTEXT, CERT_KEY_CERT_SIGN_KEY_USAGE,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CTL_USAGE, CertCloseStore,
        CertEnumCertificatesInStore, CertFindExtension, CertFreeCertificateContext,
        CertGetEnhancedKeyUsage, CertGetIntendedKeyUsage, CertOpenStore, CryptDecodeObjectEx,
        HCERTSTORE, X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, szOID_BASIC_CONSTRAINTS2,
    },
};

const MAX_CERT_BYTES: usize = 1024 * 1024;
const MAX_STORE_CERTS: usize = 16_384;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_USAGE_BYTES: usize = 16 * 1024;

struct Store(HCERTSTORE);
impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: exactly one owned, successfully opened read-only store.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

struct Enumeration {
    store: Store,
    current: *const CERT_CONTEXT,
}
impl Drop for Enumeration {
    fn drop(&mut self) {
        if !self.current.is_null() {
            // SAFETY: enumeration owns this context until the next native call.
            unsafe { CertFreeCertificateContext(self.current) };
        }
    }
}

fn visit_store(
    name: &str,
    scope: u32,
    mut visit: impl FnMut(*const CERT_CONTEXT, &[u8]) -> Result<()>,
) -> Result<()> {
    let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed local store name, explicit read-only existing-store flags.
    // Unlike CertOpenSystemStore, this cannot create a missing store.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            scope | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
            name.as_ptr().cast(),
        )
    };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code) if code == CRYPT_E_NOT_FOUND
            || code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32)
        {
            return Ok(()); // A minimal Windows installation may have no entries.
        }
        return Err(error).context("Opening read-only Windows certificate store");
    }
    let mut iterator = Enumeration {
        store: Store(handle),
        current: ptr::null(),
    };
    let mut total = 0usize;
    for _ in 0..=MAX_STORE_CERTS {
        // SAFETY: native enumeration releases the previous context even on EOF.
        let next = unsafe { CertEnumCertificatesInStore(iterator.store.0, iterator.current) };
        iterator.current = next;
        if next.is_null() {
            let error = io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(CRYPT_E_NOT_FOUND),
                "Enumerating Windows certificate store: {error}"
            );
            return Ok(());
        }
        // SAFETY: current context belongs to the live store/iterator.
        let context = unsafe { &*next };
        let length = context.cbCertEncoded as usize;
        if length == 0 || length > MAX_CERT_BYTES || context.pbCertEncoded.is_null() {
            continue;
        }
        total += length;
        ensure!(
            total <= MAX_STORE_BYTES,
            "Windows certificate store exceeds the byte limit"
        );
        // SAFETY: CryptoAPI supplies this complete DER range for the live context.
        let der = unsafe { std::slice::from_raw_parts(context.pbCertEncoded, length) };
        visit(next, der)?;
    }
    anyhow::bail!("Windows certificate store exceeds the entry limit")
}

fn ca_role(context: *const CERT_CONTEXT) -> bool {
    // SAFETY: caller retains the enumeration context throughout this function.
    let certificate = unsafe { &*context };
    if certificate.pCertInfo.is_null() {
        return false;
    }
    // SAFETY: pCertInfo is owned by that same native context.
    let info = unsafe { &*certificate.pCertInfo };
    // SAFETY: CryptoAPI supplies the extension array and accepts its native count.
    let extension =
        unsafe { CertFindExtension(szOID_BASIC_CONSTRAINTS2, info.cExtension, info.rgExtension) };
    if extension.is_null() {
        return false;
    }
    // SAFETY: extension is part of the current certificate context.
    let value = unsafe { &(*extension).Value };
    let mut basic = CERT_BASIC_CONSTRAINTS2_INFO::default();
    let mut size = size_of::<CERT_BASIC_CONSTRAINTS2_INFO>() as u32;
    // SAFETY: this particular decoder emits a fixed-size pointer-free structure.
    if unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_BASIC_CONSTRAINTS2,
            value.pbData,
            value.cbData,
            0,
            ptr::null(),
            ptr::from_mut(&mut basic).cast(),
            &mut size,
        )
    } == 0
        || basic.fCA == 0
    {
        return false;
    }
    let mut usage = [0u8; 2];
    // SAFETY: output buffer has the stated length; certificate information is live.
    if unsafe {
        CertGetIntendedKeyUsage(
            certificate.dwCertEncodingType,
            certificate.pCertInfo,
            usage.as_mut_ptr(),
            usage.len() as u32,
        )
    } != 0
    {
        usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE as u8 != 0
    } else {
        // No KeyUsage extension is unrestricted; other failures are not accepted.
        unsafe { GetLastError() as i32 == CRYPT_E_NOT_FOUND }
    }
}

fn permits_tls_server(context: *const CERT_CONTEXT) -> bool {
    let mut bytes = 0;
    // SAFETY: the first call requests the buffer size only, no certificate mutation.
    if unsafe { CertGetEnhancedKeyUsage(context, 0, ptr::null_mut(), &mut bytes) } == 0
        || !(size_of::<CTL_USAGE>()..=MAX_USAGE_BYTES).contains(&(bytes as usize))
    {
        return false;
    }
    let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    let start = storage.as_mut_ptr() as usize;
    // SAFETY: aligned storage holds at least the requested complete native result.
    unsafe { SetLastError(0) };
    let ok =
        unsafe { CertGetEnhancedKeyUsage(context, 0, storage.as_mut_ptr().cast(), &mut bytes) };
    // For zero entries Microsoft distinguishes unrestricted from disabled by this
    // value; capture it before any other native function or allocation.
    let status = unsafe { GetLastError() };
    if ok == 0 || bytes as usize > storage.len() * size_of::<usize>() {
        return false;
    }
    // SAFETY: the native result is aligned and contains the checked header size.
    let usage = unsafe { &*storage.as_ptr().cast::<CTL_USAGE>() };
    if usage.cUsageIdentifier == 0 {
        return status as i32 == CRYPT_E_NOT_FOUND;
    }
    let end = start + bytes as usize;
    let table = usage.rgpszUsageIdentifier as usize;
    let count = usage.cUsageIdentifier as usize;
    if count > 256 || table < start || table > end || count * size_of::<usize>() > end - table {
        return false;
    }
    for index in 0..count {
        // SAFETY: the complete pointer table was checked within the result above.
        let oid = unsafe { usage.rgpszUsageIdentifier.add(index).read_unaligned() } as usize;
        if oid < start || oid >= end {
            return false;
        }
        // SAFETY: bounded OID bytes are entirely within the owned native result.
        let text = unsafe { std::slice::from_raw_parts(oid as *const u8, end - oid) };
        let Some(nul) = text.iter().position(|byte| *byte == 0) else {
            return false;
        };
        if matches!(&text[..nul], b"1.3.6.1.5.5.7.3.1" | b"2.5.29.37.0") {
            return true;
        }
    }
    false
}

fn self_signed(certificate: &X509) -> bool {
    if certificate
        .subject_name()
        .try_cmp(certificate.issuer_name())
        .ok()
        != Some(std::cmp::Ordering::Equal)
    {
        return false;
    }
    certificate
        .public_key()
        .ok()
        .and_then(|key| certificate.verify(&key).ok())
        == Some(true)
}

fn consider_anchor(
    anchors: &mut BTreeMap<[u8; 32], (X509, bool)>,
    denied: &HashSet<[u8; 32]>,
    context: *const CERT_CONTEXT,
    der: &[u8],
) {
    let fingerprint = Sha256::digest(der).into();
    let Ok(certificate) = X509::from_der(der) else {
        return;
    };
    let permitted = !denied.contains(&fingerprint)
        && ca_role(context)
        && permits_tls_server(context)
        && self_signed(&certificate);
    anchors
        .entry(fingerprint)
        .and_modify(|(_, allowed)| *allowed &= permitted)
        .or_insert((certificate, permitted));
}

pub(super) fn add_to_connector(builder: &mut SslConnectorBuilder) -> Result<usize> {
    let scopes = [
        CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
    ];
    let mut denied = HashSet::<[u8; 32]>::new();
    for scope in scopes {
        visit_store("Disallowed", scope, |_, der| {
            denied.insert(Sha256::digest(der).into());
            Ok(())
        })?;
    }
    // Reject wins across duplicate contexts with different Windows EKU properties.
    let mut anchors = BTreeMap::<[u8; 32], (X509, bool)>::new();
    for scope in scopes {
        visit_store("ROOT", scope, |context, der| {
            consider_anchor(&mut anchors, &denied, context, der);
            Ok(())
        })?;
    }
    let mut count = 0;
    for (_, (certificate, permitted)) in anchors {
        if permitted {
            builder
                .cert_store_mut()
                .add_cert(certificate)
                .context("Adding Windows ROOT trust anchor to OpenSSL")?;
            count += 1;
        }
    }
    // An empty ROOT store is valid: normal verification can report an untrusted
    // chain for explicit certificate review. It never authorizes a peer by itself.
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        ssl::{SslConnector, SslMethod, SslVerifyMode},
        stack::Stack,
        x509::{
            X509NameBuilder, X509StoreContext,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    use windows_sys::Win32::Security::Cryptography::{
        CertCreateCertificateContext, CertSetEnhancedKeyUsage,
    };

    struct MemoryCertificate(*const CERT_CONTEXT);
    impl Drop for MemoryCertificate {
        fn drop(&mut self) {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
    fn native(certificate: &X509) -> MemoryCertificate {
        let der = certificate.to_der().unwrap();
        let context = unsafe {
            CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as u32)
        };
        assert!(!context.is_null());
        MemoryCertificate(context)
    }
    fn certificate(ca: bool, issuer: &str, server: Option<bool>) -> X509 {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut subject = X509NameBuilder::new().unwrap();
        subject
            .append_entry_by_text("CN", "Synthetic Windows trust test")
            .unwrap();
        let subject = subject.build();
        let mut issuer_name = X509NameBuilder::new().unwrap();
        issuer_name.append_entry_by_text("CN", issuer).unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        certificate
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        certificate.set_subject_name(&subject).unwrap();
        certificate.set_issuer_name(&issuer_name.build()).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let mut basic = BasicConstraints::new();
        basic.critical();
        if ca {
            basic.ca();
        }
        certificate
            .append_extension(basic.build().unwrap())
            .unwrap();
        let mut usage = KeyUsage::new();
        if ca {
            usage.key_cert_sign();
        } else {
            usage.digital_signature();
        }
        certificate
            .append_extension(usage.build().unwrap())
            .unwrap();
        if let Some(server) = server {
            let mut usage = ExtendedKeyUsage::new();
            if server {
                usage.server_auth();
            } else {
                usage.email_protection();
            }
            certificate
                .append_extension(usage.build().unwrap())
                .unwrap();
        }
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        certificate.build()
    }

    #[test]
    fn native_root_loading_is_read_only_bounded_and_deduplicated() {
        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        let first = add_to_connector(&mut connector).unwrap();
        let second = add_to_connector(&mut connector).unwrap();
        assert_eq!(first, second);
        let connector = connector.build();
        let certificates = connector.context().cert_store().all_certificates();
        assert!(certificates.len() >= first);
        let mut seen = HashSet::new();
        for certificate in certificates {
            assert!(seen.insert(certificate.to_der().unwrap()));
        }
        eprintln!("Windows eligible ROOT trust anchors: {first}");
    }

    #[test]
    fn native_filter_rejects_leaves_intermediates_and_non_tls_roots() {
        for (ca, issuer, server, expected) in [
            (true, "Synthetic Windows trust test", None, true),
            (true, "Synthetic Windows trust test", Some(true), true),
            (false, "Synthetic Windows trust test", Some(true), false),
            (true, "Different intermediate issuer", Some(true), false),
            (true, "Synthetic Windows trust test", Some(false), false),
        ] {
            let certificate = certificate(ca, issuer, server);
            let context = native(&certificate);
            let mut anchors = BTreeMap::new();
            consider_anchor(
                &mut anchors,
                &HashSet::new(),
                context.0,
                &certificate.to_der().unwrap(),
            );
            assert_eq!(anchors.values().next().unwrap().1, expected);
        }
    }

    #[test]
    fn native_eku_restrictions_and_explicit_distrust_win_over_duplicate_roots() {
        let certificate = certificate(true, "Synthetic Windows trust test", None);
        let der = certificate.to_der().unwrap();
        let fingerprint: [u8; 32] = Sha256::digest(&der).into();
        let context = native(&certificate);
        let mut anchors = BTreeMap::new();
        consider_anchor(&mut anchors, &HashSet::new(), context.0, &der);
        assert!(anchors[&fingerprint].1);
        let no_uses = CTL_USAGE::default();
        // These properties belong only to a detached in-memory context, not a store.
        assert_ne!(unsafe { CertSetEnhancedKeyUsage(context.0, &no_uses) }, 0);
        assert!(!permits_tls_server(context.0));
        consider_anchor(&mut anchors, &HashSet::new(), context.0, &der);
        assert_ne!(
            unsafe { CertSetEnhancedKeyUsage(context.0, ptr::null()) },
            0
        );
        assert!(permits_tls_server(context.0));
        consider_anchor(&mut anchors, &HashSet::new(), context.0, &der);
        assert!(!anchors[&fingerprint].1);
        let mut denied = HashSet::new();
        denied.insert(fingerprint);
        let mut anchors = BTreeMap::new();
        consider_anchor(&mut anchors, &denied, context.0, &der);
        assert!(!anchors[&fingerprint].1);
    }

    #[test]
    fn unrelated_generated_certificate_stays_untrusted_and_pin_policy_is_independent() {
        let root = certificate(true, "Synthetic Windows trust test", Some(true));
        let connector = crate::crypto::connector(&crate::config::Profile::default()).unwrap();
        assert!(
            connector
                .context()
                .verify_mode()
                .contains(SslVerifyMode::PEER)
        );
        let mut verification = X509StoreContext::new().unwrap();
        assert!(
            !verification
                .init(
                    connector.context().cert_store(),
                    &root,
                    &Stack::new().unwrap(),
                    |context| context.verify_cert()
                )
                .unwrap()
        );
        let pinned = crate::crypto::connector(&crate::config::Profile {
            certificate_sha256: "00".repeat(32),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(pinned.context().verify_mode(), SslVerifyMode::NONE);
    }
}
