import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Modal } from "./Modal";

type InstallOptionsDialogProps = {
  appPath: string;
  onCancel: () => void;
  onInstall: (bundleId: string | null) => void;
};

export function InstallOptionsDialog({
  appPath,
  onCancel,
  onInstall,
}: InstallOptionsDialogProps) {
  const { t } = useTranslation();
  const [bundleId, setBundleId] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const submittedRef = useRef(false);
  const normalizedBundleId = bundleId.trim();
  const validBundleId =
    normalizedBundleId === "" ||
    /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(normalizedBundleId);
  const fileName = appPath.split(/[\\/]/).pop() || appPath;

  useEffect(() => {
    const previousFocus = document.activeElement;
    inputRef.current?.focus();
    return () => {
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) {
        previousFocus.focus();
      }
    };
  }, []);

  return (
    <Modal isOpen close={onCancel} sizeFit hideClose>
      <section
        className="install-options"
        role="dialog"
        aria-modal="true"
        aria-labelledby="install-options-title"
        aria-describedby="install-options-file"
        onKeyDown={(event) => {
          if (event.key !== "Tab") return;
          const focusable = event.currentTarget.querySelectorAll<HTMLElement>(
            "input:not(:disabled), button:not(:disabled)",
          );
          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
          }
        }}
      >
        <h2 id="install-options-title">{t("install_options.title")}</h2>
        <p id="install-options-file" className="install-options-file">
          <span>{t("install_options.selected_file")}</span>
          <strong>{fileName}</strong>
        </p>
        <form
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            if (!validBundleId || submittedRef.current) return;
            submittedRef.current = true;
            onInstall(normalizedBundleId || null);
          }}
        >
          <label htmlFor="install-bundle-id">
            {t("install_options.bundle_id")}
          </label>
          <input
            ref={inputRef}
            id="install-bundle-id"
            name="bundleId"
            type="text"
            value={bundleId}
            placeholder="com.example.myapp"
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            aria-invalid={!validBundleId}
            aria-describedby={
              validBundleId
                ? "install-bundle-id-help"
                : "install-bundle-id-help install-bundle-id-error"
            }
            onChange={(event) => setBundleId(event.target.value)}
          />
          <p id="install-bundle-id-help" className="install-options-help">
            {t("install_options.bundle_id_help")}
          </p>
          {!validBundleId && (
            <p
              id="install-bundle-id-error"
              className="install-options-error"
              role="alert"
            >
              {t("install_options.invalid_bundle_id")}
            </p>
          )}
          <p className="install-options-note">
            {t("install_options.bundle_id_note")}
          </p>
          <div className="install-options-actions">
            <button type="button" onClick={onCancel}>
              {t("common.cancel")}
            </button>
            <button
              type="submit"
              className="action-button primary"
              disabled={!validBundleId}
            >
              {t("install_options.install")}
            </button>
          </div>
        </form>
      </section>
    </Modal>
  );
}
