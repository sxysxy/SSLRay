# Version-matched upstream notices

Some published Rust crates omit the repository-level license files. This
directory preserves the missing upstream text for the exact published versions
used by SSLRay. It does not modify the Cargo registry or execute upstream code.

`manifest.json` binds every entry to the crate name, version, Cargo.lock archive
SHA-256, declared repository/license, and the revision/path recorded in the
published archive's `.cargo_vcs_info.json`. During curation, each archive was
checked against Cargo.lock, and fetched files were checked against their Git
tree blob IDs at that revision. Files under `files/` retain their original bytes.

AccessKit's copyright/Chromium attribution and tun's complete WTFPL grant are
leading source comments rather than independent notice files. Their checked-in
excerpts preserve those comment lines verbatim. The manifest records the source
URL, full-source SHA-256, upstream Git blob and inclusive line range separately
from the excerpt SHA-256. No copyright holder or year has been invented.
AccessKit's original AUTHORS and Chromium license are also retained. Egui's
existing crate-local font notices continue to be collected independently.

The collector runs offline. It applies a supplement only when the current
package/version, lockfile checksum, repository, declared license and published
VCS revision/path match. It verifies every checked-in notice SHA-256 and also
checks the registry archive when that archive is present. Bundled INDEX.json
records the installed files and pinned source provenance per component. A
changed crate version or checksum requires a newly reviewed mapping.

The `notice_state` values describe the available upstream evidence:

- `full_text`: the selected original notices contain the license text and any
  available upstream attribution. This is not a claim of a complete legal audit.
- `policy_only`: seven newer objc2-family versions provide only a repository
  licensing-policy document at the recorded revision. That actual document is
  copied, and the full-text/attribution gap stays explicit in
  `INDEX.json.upstream_notice_limitations`.
- `unavailable`: dispatch 0.2.0 declares MIT, but its recorded repository tree
  contains no independent license/notice file. Its missing-notice entry remains;
  a generic template or another version's copyright text is not substituted.

The exact objc2 revision's [licensing policy](https://github.com/madsmtm/objc2/blob/b4167b582b2f75f9a1be75495c41b765344fd03c/LICENSE.md)
and the upstream [missing-license issue](https://github.com/madsmtm/objc2/issues/826)
explain the distinction. The older full MIT notices are copied only for the
versions whose own published revisions contain them. Sources and checksums for
each individual file are in the manifest.
