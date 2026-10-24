//! Exercise the extracted-file preparation used by real signing calls without
//! an Apple account, device, or network.

use super::remove_app_extensions;
use crate::sideload::{
    SideloadOptions, application::Application, builder::ExtensionsBehavior, bundle::Bundle,
};
use plist::{Dictionary, Value};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zip::{ZipWriter, write::SimpleFileOptions};

const ORIGINAL_ID: &str = "com.example.original";

struct Fixture {
    directory: PathBuf,
    ipa: PathBuf,
    extractions: RefCell<Vec<PathBuf>>,
}

impl Fixture {
    fn new(with_extensions: bool, with_embedded_apps: bool) -> Self {
        let name = format!("iloader-extensions-{}", Uuid::new_v4());
        let directory = std::env::temp_dir().join(&name);
        fs::create_dir_all(&directory).unwrap();
        let ipa = directory.join(format!("{name}.ipa"));
        let mut archive = ZipWriter::new(fs::File::create(&ipa).unwrap());
        write_bundle(&mut archive, "", ORIGINAL_ID);
        write_bundle(
            &mut archive,
            "Frameworks/Library.framework/",
            "com.example.Library",
        );
        for (path, bytes) in [
            ("Fixture", b"main executable".as_slice()),
            ("Assets.car", b"main assets".as_slice()),
            (
                "Frameworks/Library.framework/Library",
                b"framework".as_slice(),
            ),
            ("Frameworks/MainHelper.dylib", b"main dylib".as_slice()),
            ("PlugIns/Readme.txt", b"keep plugin resource".as_slice()),
            (
                "PlugIns/File.appex",
                b"a regular file, not an extension".as_slice(),
            ),
            (
                "PlugIns/Support.bundle/asset",
                b"non-extension plugin".as_slice(),
            ),
            (
                "Resources/Backup.appex.backup/asset",
                b"not an appex".as_slice(),
            ),
        ] {
            write_file(&mut archive, path, bytes);
        }
        if with_extensions {
            for (directory, id) in [
                ("PlugIns/Widget.appex/", "com.example.original.widget"),
                // This malformed identifier must not block a custom ID when
                // the extension is deliberately removed first.
                ("PlugIns/Share.appex/", "com.unrelated.share"),
                (
                    "PlugIns/Widget.appex/PlugIns/Nested.appex/",
                    "com.example.original.widget.nested",
                ),
                (
                    "Frameworks/Library.framework/PlugIns/Deep.appex/",
                    "com.example.Library.deep",
                ),
            ] {
                write_bundle(&mut archive, directory, id);
            }
            write_file(
                &mut archive,
                "PlugIns/Widget.appex/Frameworks/ExtensionHelper.dylib",
                b"extension dylib",
            );
            write_file(
                &mut archive,
                "PlugIns/Broken.appex/Info.plist",
                b"this is not a property list",
            );
            write_file(
                &mut archive,
                "Resources/Hidden.appex/asset",
                b"no Info.plist, still an appex directory",
            );
            archive
                .add_directory(
                    "Payload/Fixture.app/PlugIns/Empty.appex/",
                    SimpleFileOptions::default(),
                )
                .unwrap();
        }
        if with_embedded_apps {
            for directory in ["Watch/Companion.app/", "AppClips/Clip.app/"] {
                write_bundle(&mut archive, directory, "com.example.original.child");
                write_file(&mut archive, &format!("{directory}Child"), b"embedded app");
                if with_extensions {
                    write_bundle(
                        &mut archive,
                        &format!("{directory}PlugIns/Child.appex/"),
                        "com.example.original.child.extension",
                    );
                }
            }
        }
        archive.finish().unwrap();
        Self {
            directory,
            ipa,
            extractions: RefCell::new(Vec::new()),
        }
    }

    fn record(&self, app: Application) -> Application {
        self.extractions.borrow_mut().push(
            app.bundle
                .bundle_dir
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .to_path_buf(),
        );
        app
    }

    fn load(&self, options: SideloadOptions<'_>) -> Application {
        self.record(
            Application::new_with_extension_removal(self.ipa.clone(), options.remove_extensions)
                .unwrap(),
        )
    }

    fn load_default(&self) -> Application {
        self.record(Application::new(self.ipa.clone()).unwrap())
    }

    #[cfg(unix)]
    fn add_symlink(&self, path: &str, target: &str) {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.ipa)
            .unwrap();
        let mut archive = ZipWriter::new_append(file).unwrap();
        archive
            .add_symlink(
                format!("Payload/Fixture.app/{path}"),
                target,
                SimpleFileOptions::default(),
            )
            .unwrap();
        archive.finish().unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for directory in self.extractions.get_mut() {
            let _ = fs::remove_dir_all(directory);
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn write_file(archive: &mut ZipWriter<fs::File>, path: &str, bytes: &[u8]) {
    archive
        .start_file(
            format!("Payload/Fixture.app/{path}"),
            SimpleFileOptions::default(),
        )
        .unwrap();
    archive.write_all(bytes).unwrap();
}

fn write_bundle(archive: &mut ZipWriter<fs::File>, directory: &str, id: &str) {
    let mut info = Dictionary::new();
    info.insert("CFBundleIdentifier".into(), Value::String(id.into()));
    info.insert("CFBundleName".into(), Value::String("Fixture".into()));
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &info).unwrap();
    write_file(archive, &format!("{directory}Info.plist"), &bytes);
}

fn removal_options() -> SideloadOptions<'static> {
    SideloadOptions {
        remove_extensions: true,
        ..SideloadOptions::default()
    }
}

fn snapshot_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                result.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    result
}

fn inside_extension(path: &Path) -> bool {
    // Only ancestors are relevant: a regular file called File.appex stays.
    path.parent().unwrap().ancestors().any(|ancestor| {
        ancestor
            .extension()
            .is_some_and(|extension| extension == "appex")
    })
}

#[test]
fn absent_and_false_options_preserve_extension_files_and_models() {
    let fixture = Fixture::new(true, false);
    let original_ipa = fs::read(&fixture.ipa).unwrap();
    let app = fixture.load_default();
    let before = snapshot_files(&app.bundle.bundle_dir);
    assert_eq!(app.bundle.app_extensions().len(), 2);
    assert!(
        app.bundle
            .collect_nested_bundles()
            .iter()
            .any(|bundle| bundle.bundle_dir.ends_with("ExtensionHelper.dylib"))
    );

    let app = fixture.load(SideloadOptions::default());
    assert_eq!(snapshot_files(&app.bundle.bundle_dir), before);
    assert_eq!(app.bundle.app_extensions().len(), 2);
    assert!(app.bundle.bundle_dir.join("PlugIns/Broken.appex").is_dir());
    assert!(app.bundle.bundle_dir.join("PlugIns/Empty.appex").is_dir());
    assert_eq!(fs::read(&fixture.ipa).unwrap(), original_ipa);
}

#[test]
fn removes_all_real_extension_directories_and_rebuilds_bundle_model() {
    let fixture = Fixture::new(true, true);
    let original_ipa = fs::read(&fixture.ipa).unwrap();
    let original = fixture.load_default();
    let before = snapshot_files(&original.bundle.bundle_dir);
    let app = fixture.load(removal_options());
    let expected = before
        .iter()
        .filter(|(path, _)| !inside_extension(path))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect();
    assert_eq!(snapshot_files(&app.bundle.bundle_dir), expected);
    assert!(app.bundle.app_extensions().is_empty());
    assert_eq!(app.bundle.frameworks().len(), 1);
    assert!(app.bundle.frameworks()[0].app_extensions().is_empty());
    let nested = app.bundle.collect_nested_bundles();
    assert!(
        !nested
            .iter()
            .any(|bundle| inside_extension(&bundle.bundle_dir))
    );
    assert!(
        nested
            .iter()
            .any(|bundle| bundle.bundle_dir.ends_with("MainHelper.dylib"))
    );
    for directory in ["Watch/Companion.app", "AppClips/Clip.app"] {
        assert!(app.bundle.bundle_dir.join(directory).is_dir());
        assert!(
            !app.bundle
                .bundle_dir
                .join(directory)
                .join("PlugIns/Child.appex")
                .exists()
        );
    }
    assert!(!app.bundle.bundle_dir.join("PlugIns/Empty.appex").exists());
    assert!(app.bundle.bundle_dir.join("PlugIns/File.appex").is_file());
    for mode in [
        ExtensionsBehavior::RegisterAll,
        ExtensionsBehavior::ReuseMain,
    ] {
        assert_eq!(app.bundles_to_register(&mode).len(), 1);
    }
    assert_eq!(fs::read(&fixture.ipa).unwrap(), original_ipa);
    // The second extraction was isolated; another source app copy is intact.
    assert_eq!(snapshot_files(&original.bundle.bundle_dir), before);
}

#[test]
fn removal_count_includes_nested_and_malformed_extension_directories() {
    let fixture = Fixture::new(true, true);
    let app = fixture.load_default();
    assert_eq!(remove_app_extensions(&app.bundle.bundle_dir).unwrap(), 9);
    assert_eq!(remove_app_extensions(&app.bundle.bundle_dir).unwrap(), 0);
}

#[test]
fn custom_id_runs_after_removal_and_the_option_is_not_sticky() {
    let fixture = Fixture::new(true, false);
    let mut unchanged = fixture.load_default();
    assert!(
        unchanged
            .prepare_bundle_id("TEAM123", Some("net.tim.copy"))
            .is_err()
    );

    let mut app = fixture.load(removal_options());
    assert_eq!(
        app.prepare_bundle_id("TEAM123", Some("net.tim.copy"))
            .unwrap(),
        "net.tim.copy"
    );
    assert_eq!(
        app.bundles_to_register(&ExtensionsBehavior::RegisterAll)
            .len(),
        1
    );

    let next = fixture.load(SideloadOptions::default());
    assert_eq!(next.main_bundle_id().unwrap(), ORIGINAL_ID);
    assert_eq!(next.bundle.app_extensions().len(), 2);
    assert!(
        next.bundle
            .bundle_dir
            .join("PlugIns/Widget.appex/PlugIns/Nested.appex")
            .is_dir()
    );
}

#[test]
fn removing_extensions_preserves_embedded_app_layout_guard() {
    let fixture = Fixture::new(true, true);
    let mut app = fixture.load(removal_options());
    let error = app
        .prepare_bundle_id("TEAM123", Some("net.tim.copy"))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Custom bundle IDs are not supported")
    );
    assert_eq!(
        app.prepare_bundle_id("TEAM123", None).unwrap(),
        "com.example.original.TEAM123"
    );
}

#[test]
fn no_extension_ipa_is_unchanged() {
    let fixture = Fixture::new(false, false);
    let original_ipa = fs::read(&fixture.ipa).unwrap();
    let app = fixture.load_default();
    let before = snapshot_files(&app.bundle.bundle_dir);
    let prepared = fixture.load(removal_options());
    assert_eq!(snapshot_files(&prepared.bundle.bundle_dir), before);
    assert_eq!(fs::read(&fixture.ipa).unwrap(), original_ipa);
}

#[test]
fn direct_app_directory_with_extensions_is_rejected_without_changes() {
    let fixture = Fixture::new(true, false);
    let app = fixture.load_default();
    let before = snapshot_files(&app.bundle.bundle_dir);
    let error = Application::new_with_extension_removal(app.bundle.bundle_dir.clone(), true)
        .err()
        .expect("must reject a source app directory");
    assert!(error.to_string().contains("requires an IPA archive"));
    assert_eq!(snapshot_files(&app.bundle.bundle_dir), before);
}

#[cfg(unix)]
#[test]
fn retained_symlinks_are_rejected_before_any_extension_is_deleted() {
    for link in ["PlugIns/Linked.appex", "ResourceLink", "PlugIns"] {
        let fixture = Fixture::new(true, false);
        let app = fixture.load_default();
        let outside = fixture.directory.join("outside");
        fs::create_dir_all(outside.join("External.appex")).unwrap();
        fs::write(outside.join("External.appex/sentinel"), b"must survive").unwrap();
        let real_plugins = if link == "PlugIns" {
            let saved = app.bundle.bundle_dir.join("SavedPlugIns");
            fs::rename(app.bundle.bundle_dir.join("PlugIns"), &saved).unwrap();
            saved
        } else {
            app.bundle.bundle_dir.join("PlugIns")
        };
        std::os::unix::fs::symlink(&outside, app.bundle.bundle_dir.join(link)).unwrap();
        let before = snapshot_files(&app.bundle.bundle_dir);
        let error = remove_app_extensions(&app.bundle.bundle_dir).unwrap_err();
        assert!(error.to_string().contains("retained symbolic link"));
        assert_eq!(snapshot_files(&app.bundle.bundle_dir), before);
        assert!(real_plugins.join("Empty.appex").is_dir());
        assert_eq!(
            fs::read(outside.join("External.appex/sentinel")).unwrap(),
            b"must survive"
        );
    }
}

#[cfg(unix)]
#[test]
fn links_inside_removed_extensions_do_not_touch_external_targets() {
    let fixture = Fixture::new(true, false);
    let app = fixture.load_default();
    let outside = fixture.directory.join("outside.appex");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"must survive").unwrap();
    std::os::unix::fs::symlink(
        &outside,
        app.bundle
            .bundle_dir
            .join("PlugIns/Widget.appex/External.appex"),
    )
    .unwrap();
    assert_eq!(remove_app_extensions(&app.bundle.bundle_dir).unwrap(), 7);
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"must survive");
    assert!(!app.bundle.bundle_dir.join("PlugIns/Widget.appex").exists());
    let rebuilt = Bundle::new(app.bundle.bundle_dir).unwrap();
    assert!(rebuilt.app_extensions().is_empty());
}

#[cfg(unix)]
#[test]
fn archived_retained_link_is_rejected_before_bundle_model_can_follow_it() {
    let fixture = Fixture::new(true, false);
    // An internal cycle would recurse during legacy bundle loading, so this
    // verifies rejection occurs before constructing that model.
    fixture.add_symlink("Resources/Loop", "..");
    let original_ipa = fs::read(&fixture.ipa).unwrap();
    let error = Application::new_with_extension_removal(fixture.ipa.clone(), true)
        .err()
        .expect("must reject retained archive symlinks");
    assert!(format!("{error:?}").contains("retained symbolic link"));
    assert_eq!(fs::read(&fixture.ipa).unwrap(), original_ipa);
}
