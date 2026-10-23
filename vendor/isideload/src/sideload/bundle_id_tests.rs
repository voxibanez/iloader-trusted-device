//! Offline IPA fixtures exercise the same preparation step used before App ID
//! registration and signing. No Apple account, device, or network is needed.
use super::normalize_bundle_id;
use crate::sideload::{application::Application, builder::ExtensionsBehavior};
use plist::{Dictionary, Value};
use std::{fs, io::Write, path::PathBuf};
use uuid::Uuid;
use zip::{ZipWriter, write::SimpleFileOptions};

const ORIGINAL_ID: &str = "com.example.original";
const CUSTOM_ID: &str = "net.tim.my-app";

struct Fixture {
    directory: PathBuf,
    ipa: PathBuf,
    extracted: PathBuf,
}

impl Fixture {
    fn new(extension_ids: &[&str]) -> Self {
        let unique_name = format!("iloader-bundle-id-{}", Uuid::new_v4());
        let directory = std::env::temp_dir().join(&unique_name);
        fs::create_dir_all(&directory).unwrap();
        let filename = format!("{unique_name}.ipa");
        let ipa = directory.join(&filename);
        let extracted = std::env::temp_dir().join(format!("{filename}_extracted"));
        let mut archive = ZipWriter::new(fs::File::create(&ipa).unwrap());

        fn write_plist(archive: &mut ZipWriter<fs::File>, path: &str, info: &Dictionary) {
            let mut bytes = Vec::new();
            plist::to_writer_xml(&mut bytes, info).unwrap();
            archive
                .start_file(path, SimpleFileOptions::default())
                .unwrap();
            archive.write_all(&bytes).unwrap();
        }

        fn bundle_info(id: &str, name: &str) -> Dictionary {
            let mut info = Dictionary::new();
            info.insert("CFBundleIdentifier".into(), Value::String(id.into()));
            info.insert("CFBundleName".into(), Value::String(name.into()));
            info.insert(
                "BGTaskSchedulerPermittedIdentifiers".into(),
                Value::Array(vec![
                    Value::String(format!("{id}.fetch")),
                    Value::String(format!("{id}ish.fetch")),
                    Value::String(format!("prefix.{id}.fetch")),
                ]),
            );
            info.insert("TestDescription".into(), Value::String(format!("URL {id}")));
            info
        }

        write_plist(
            &mut archive,
            "Payload/Fixture.app/Info.plist",
            &bundle_info(ORIGINAL_ID, "Fixture"),
        );
        for (index, id) in extension_ids.iter().enumerate() {
            let mut info = bundle_info(id, &format!("Extension{index}"));
            info.insert(
                "WKCompanionAppBundleIdentifier".into(),
                Value::String(ORIGINAL_ID.into()),
            );
            let mut attributes = Dictionary::new();
            attributes.insert(
                "WKAppBundleIdentifier".into(),
                Value::String(format!("{ORIGINAL_ID}.watch")),
            );
            let mut extension = Dictionary::new();
            extension.insert(
                "NSExtensionAttributes".into(),
                Value::Dictionary(attributes),
            );
            info.insert("NSExtension".into(), Value::Dictionary(extension));
            write_plist(
                &mut archive,
                &format!("Payload/Fixture.app/PlugIns/Extension{index}.appex/Info.plist"),
                &info,
            );
        }
        write_plist(
            &mut archive,
            "Payload/Fixture.app/Frameworks/Library.framework/Info.plist",
            &bundle_info("com.example.original.Library", "Library"),
        );
        archive.finish().unwrap();

        Self {
            directory,
            ipa,
            extracted,
        }
    }

    fn load(&self) -> Application {
        Application::new(self.ipa.clone()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.extracted);
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn ids_for_registration(app: &Application, mode: ExtensionsBehavior) -> Vec<String> {
    let mut ids: Vec<_> = app
        .bundles_to_register(&mode)
        .iter()
        .map(|bundle| bundle.bundle_identifier().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

#[test]
fn validates_and_normalizes_custom_bundle_ids() {
    for absent in [None, Some(""), Some(" \t\n")] {
        assert_eq!(normalize_bundle_id(absent).unwrap(), None);
    }
    for valid in ["com.example.app", "net.Tim.My-App2", "123.example.456"] {
        assert_eq!(
            normalize_bundle_id(Some(valid)).unwrap().as_deref(),
            Some(valid)
        );
    }
    assert_eq!(
        normalize_bundle_id(Some("  net.tim.my-app \n"))
            .unwrap()
            .as_deref(),
        Some(CUSTOM_ID),
    );
    for invalid in [
        "app",
        ".com.app",
        "com.app.",
        "com..app",
        "com.my_app",
        "com.*",
        "com/my.app",
        "com.äpfel",
        "com.my app",
        "com.my\napp",
    ] {
        assert!(
            normalize_bundle_id(Some(invalid)).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn custom_id_and_extensions_are_exact_and_used_for_registration() {
    let fixture = Fixture::new(&["com.example.original.widget", "com.example.original.share"]);
    let mut app = fixture.load();
    assert_eq!(
        app.prepare_bundle_id("TEAM123", Some(CUSTOM_ID)).unwrap(),
        CUSTOM_ID
    );
    assert_eq!(app.main_bundle_id().unwrap(), CUSTOM_ID);
    assert_eq!(
        ids_for_registration(&app, ExtensionsBehavior::RegisterAll),
        [CUSTOM_ID, "net.tim.my-app.share", "net.tim.my-app.widget"],
    );
    assert_eq!(
        ids_for_registration(&app, ExtensionsBehavior::ReuseMain),
        [CUSTOM_ID],
    );
    assert_eq!(
        app.bundle.frameworks()[0].bundle_identifier(),
        Some("com.example.original.Library")
    );
}

#[test]
fn blank_and_absent_overrides_preserve_default_team_suffix() {
    for selected in [None, Some(" \t")] {
        let fixture = Fixture::new(&["com.example.original.widget"]);
        let mut app = fixture.load();
        assert_eq!(
            app.prepare_bundle_id("TEAM123", selected).unwrap(),
            "com.example.original.TEAM123",
        );
        assert_eq!(
            ids_for_registration(&app, ExtensionsBehavior::RegisterAll),
            [
                "com.example.original.TEAM123",
                "com.example.original.TEAM123.widget"
            ],
        );
    }
}

#[test]
fn override_is_not_remembered_for_next_ipa() {
    let first = Fixture::new(&[]);
    let second = Fixture::new(&[]);
    assert_eq!(
        first
            .load()
            .prepare_bundle_id("TEAM123", Some(CUSTOM_ID))
            .unwrap(),
        CUSTOM_ID
    );
    assert_eq!(
        second.load().prepare_bundle_id("TEAM123", None).unwrap(),
        "com.example.original.TEAM123"
    );
}

#[test]
fn invalid_override_and_lookalike_extension_leave_bundle_ids_unchanged() {
    let valid = Fixture::new(&["com.example.original.widget"]);
    let mut app = valid.load();
    assert!(
        app.prepare_bundle_id("TEAM123", Some("com.bad id"))
            .is_err()
    );
    assert_eq!(app.main_bundle_id().unwrap(), ORIGINAL_ID);
    assert_eq!(
        app.bundle.app_extensions()[0].bundle_identifier(),
        Some("com.example.original.widget")
    );

    let malformed = Fixture::new(&[
        "com.example.original.widget",
        "com.example.originalish.share",
    ]);
    let mut app = malformed.load();
    let before = ids_for_registration(&app, ExtensionsBehavior::RegisterAll);
    assert!(app.prepare_bundle_id("TEAM123", Some(CUSTOM_ID)).is_err());
    assert_eq!(
        ids_for_registration(&app, ExtensionsBehavior::RegisterAll),
        before
    );
}

#[test]
fn writes_changed_plists_without_altering_source_ipa_or_unrelated_values() {
    let fixture = Fixture::new(&["com.example.original.widget"]);
    let original_archive = fs::read(&fixture.ipa).unwrap();
    let mut app = fixture.load();
    app.prepare_bundle_id("TEAM123", Some(CUSTOM_ID)).unwrap();
    app.bundle.write_info().unwrap();
    for extension in app.bundle.app_extensions() {
        extension.write_info().unwrap();
    }

    let rewritten = Application::new(app.bundle.bundle_dir.clone()).unwrap();
    assert_eq!(rewritten.main_bundle_id().unwrap(), CUSTOM_ID);
    let tasks = rewritten.bundle.app_info["BGTaskSchedulerPermittedIdentifiers"]
        .as_array()
        .unwrap();
    assert_eq!(tasks[0].as_string(), Some("net.tim.my-app.fetch"));
    assert_eq!(tasks[1].as_string(), Some("com.example.originalish.fetch"));
    assert_eq!(
        tasks[2].as_string(),
        Some("prefix.com.example.original.fetch")
    );
    assert_eq!(
        rewritten.bundle.app_info["TestDescription"].as_string(),
        Some("URL com.example.original")
    );

    let extension = &rewritten.bundle.app_extensions()[0];
    assert_eq!(extension.bundle_identifier(), Some("net.tim.my-app.widget"));
    assert_eq!(
        extension.app_info["WKCompanionAppBundleIdentifier"].as_string(),
        Some(CUSTOM_ID)
    );
    let attributes =
        extension.app_info["NSExtension"].as_dictionary().unwrap()["NSExtensionAttributes"]
            .as_dictionary()
            .unwrap();
    assert_eq!(
        attributes["WKAppBundleIdentifier"].as_string(),
        Some("net.tim.my-app.watch")
    );
    assert_eq!(fs::read(&fixture.ipa).unwrap(), original_archive);
    assert_eq!(fixture.load().main_bundle_id().unwrap(), ORIGINAL_ID);
}

#[test]
fn custom_ids_reject_unsupported_embedded_layouts_without_changing_default_path() {
    for child_path in [
        "Watch/Companion.app",
        "AppClips/Clip.app",
        "PlugIns/Extension0.appex/PlugIns/Nested.appex",
    ] {
        let fixture = Fixture::new(&["com.example.original.widget"]);
        let app = fixture.load();
        let child_dir = app.bundle.bundle_dir.join(child_path);
        fs::create_dir_all(&child_dir).unwrap();
        let mut child_info = Dictionary::new();
        child_info.insert(
            "CFBundleIdentifier".into(),
            Value::String("com.example.original.widget.child".into()),
        );
        child_info.insert("CFBundleName".into(), Value::String("Child".into()));
        plist::to_file_xml(child_dir.join("Info.plist"), &child_info).unwrap();

        let mut app = Application::new(app.bundle.bundle_dir).unwrap();
        let error = app
            .prepare_bundle_id("TEAM123", Some(CUSTOM_ID))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Custom bundle IDs are not supported"),
            "{error}"
        );
        assert_eq!(app.main_bundle_id().unwrap(), ORIGINAL_ID);
        assert_eq!(
            app.prepare_bundle_id("TEAM123", None).unwrap(),
            "com.example.original.TEAM123"
        );
    }
}
